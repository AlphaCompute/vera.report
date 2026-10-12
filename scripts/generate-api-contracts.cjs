// Generate response shapes from the same TypeScript expressions sent by Express.
// JSDoc remains authoritative for descriptions and manually specified schemas.
const ts = require('typescript');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const config = ts.readConfigFile(path.join(root, 'tsconfig.json'), ts.sys.readFile);
const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root);
const program = ts.createProgram(parsed.fileNames, parsed.options);
const checker = program.getTypeChecker();
const prefixes = { server: '', whistleblower: '/api/whistleblower', audit: '/api/admin', dissemination: '/api/dissemination' };
function shape(type, depth = 0, seen = new Set()) {
  const f = ts.TypeFlags;
  if (type.flags & (f.Any | f.Unknown)) return {};
  if (type.flags & f.StringLike) return { type: 'string', ...(type.flags & f.StringLiteral ? { enum: [type.value] } : {}) };
  if (type.flags & f.NumberLike) return { type: 'number' };
  if (type.flags & f.BooleanLike) return { type: 'boolean' };
  if (type.flags & f.BigIntLike) return { type: 'string', description: 'Serialized integer' };
  if (type.isUnion()) {
    const nullable = type.types.some(t => t.flags & f.Null);
    const branches = type.types.filter(t => !(t.flags & (f.Null | f.Undefined | f.Never))).map(t => shape(t, depth, seen));
    const unique = [...new Map(branches.map(s => [JSON.stringify(s), s])).values()];
    const result = unique.length === 1 ? { ...unique[0] } : unique.length ? { anyOf: unique } : {};
    if (nullable) result.nullable = true;
    return result;
  }
  if (checker.isArrayType(type) || checker.isTupleType(type)) {
    const element = checker.getIndexTypeOfType(type, ts.IndexKind.Number);
    return { type: 'array', items: element && depth < 6 ? shape(element, depth + 1, seen) : {} };
  }
  const name = type.getSymbol()?.getName();
  if (name === 'Date') return { type: 'string', format: 'date-time' };
  if (name === 'Buffer' || name === 'Uint8Array') return { type: 'object', properties: { type: { type: 'string' }, data: { type: 'array', items: { type: 'integer' } } } };
  if (depth >= 6 || seen.has(type)) return { type: 'object', additionalProperties: true };
  const nextSeen = new Set(seen).add(type);
  const properties = {}, required = [];
  for (const symbol of checker.getPropertiesOfType(type)) {
    const declaration = symbol.valueDeclaration || symbol.declarations?.[0];
    if (!declaration || symbol.flags & (ts.SymbolFlags.Method | ts.SymbolFlags.Function)) continue;
    if (ts.getCombinedModifierFlags(declaration) & (ts.ModifierFlags.Private | ts.ModifierFlags.Protected)) continue;
    const valueType = checker.getTypeOfSymbolAtLocation(symbol, declaration);
    properties[symbol.getName()] = shape(valueType, depth + 1, nextSeen);
    if (!(symbol.flags & ts.SymbolFlags.Optional) && !(valueType.isUnion() && valueType.types.some(t => t.flags & f.Undefined))) required.push(symbol.getName());
  }
  const result = { type: 'object', properties };
  if (required.length) result.required = required;
  const index = checker.getIndexTypeOfType(type, ts.IndexKind.String);
  if (index) result.additionalProperties = shape(index, depth + 1, nextSeen);
  return result;
}
function visit(node, fn) { fn(node); ts.forEachChild(node, child => visit(child, fn)); }
const contracts = {};
for (const [file, prefix] of Object.entries(prefixes)) {
  const source = program.getSourceFile(path.join(root, `src/api/${file}.ts`));
  visit(source, node => {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
    const method = node.expression.name.text;
    if (!['get', 'post', 'put', 'patch', 'delete'].includes(method) || !['app', 'router'].includes(node.expression.expression.getText(source))) return;
    if (!node.arguments[0] || !ts.isStringLiteral(node.arguments[0])) throw new Error('Dynamic route must be documented explicitly');
    const route = (prefix + node.arguments[0].text).replace(/:([A-Za-z0-9_]+)/g, '{$1}');
    const responses = {}, bodyFields = new Set(), queryFields = new Set();
    let internal = node.arguments.some(a => a.getText(source) === 'requireInternalSecret') || file === 'audit';
    for (const handler of node.arguments.slice(1).flatMap(a => ts.isCallExpression(a) && a.expression.getText(source) === 'withUploadBudget' ? [...a.arguments] : [a]).filter(a => ts.isArrowFunction(a) || ts.isFunctionExpression(a))) visit(handler, n => {
      if (ts.isVariableDeclaration(n) && ts.isObjectBindingPattern(n.name) && n.initializer && /^req\.body(?:\s*\?\?.*)?$/.test(n.initializer.getText(source))) {
        for (const element of n.name.elements) bodyFields.add((element.propertyName || element.name).getText(source));
      }
      if (ts.isPropertyAccessExpression(n) && n.expression.getText(source) === 'req.body') bodyFields.add(n.name.text);
      if (ts.isPropertyAccessExpression(n) && n.expression.getText(source) === 'req.query') queryFields.add(n.name.text);
      if (ts.isVariableDeclaration(n) && ts.isObjectBindingPattern(n.name) && n.initializer?.getText(source) === 'req.query') for (const element of n.name.elements) queryFields.add((element.propertyName || element.name).getText(source));
      if (!ts.isCallExpression(n) || !ts.isPropertyAccessExpression(n.expression) || n.expression.name.text !== 'json' || !n.arguments[0]) return;
      let chain = n.expression.expression, status = '200';
      while (ts.isCallExpression(chain) && ts.isPropertyAccessExpression(chain.expression)) {
        if (chain.expression.name.text === 'status') status = chain.arguments[0] && ts.isNumericLiteral(chain.arguments[0]) ? chain.arguments[0].text : 'default';
        chain = chain.expression.expression;
      }
      if (chain.getText(source) !== 'res') return;
      const schema = shape(checker.getTypeAtLocation(n.arguments[0]));
      (responses[status] ||= []).push(schema);
    });
    for (const status of Object.keys(responses)) {
      const distinct = [...new Map(responses[status].map(s => [JSON.stringify(s), s])).values()];
      responses[status] = distinct.length === 1 ? distinct[0] : { anyOf: distinct };
    }
    contracts[`${method.toUpperCase()} ${route}`] = { security: internal ? 'internal' : 'public', bodyFields: [...bodyFields].sort(), queryFields: [...queryFields].sort(), responses };
  });
}
const content = JSON.stringify(contracts, null, 2) + '\n';
const output = path.join(root, 'src/docs/api-contracts.json');
if (process.argv.includes('--check')) {
  if (fs.readFileSync(output, 'utf8') !== content) throw new Error('API contracts changed; run node scripts/generate-api-contracts.cjs');
} else fs.writeFileSync(output, content);
console.log(`Checked ${Object.keys(contracts).length} Express operations`);
