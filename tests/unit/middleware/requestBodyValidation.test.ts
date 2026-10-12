import express from 'express';
import request from 'supertest';
import { validateRequestBody } from '../../../src/middleware/security';

function app() {
    const server = express();
    server.use(express.json());
    server.use(validateRequestBody);
    server.post('/', (req, res) => res.json(req.body));
    return server;
}

describe('Request body structural validation', () => {
    it('preserves nested strings, JSON text, arrays and long field names', async () => {
        const body = {
            narrative: '  <script>"quoted" & O\'Brien</script>\n',
            nested: [{ selection: '{"author":false}', enabled: false, count: 0, empty: null }],
            ['field'.repeat(30)]: 'preserved',
        };
        const response = await request(app()).post('/').send(body);
        expect(response.status).toBe(200);
        expect(response.body).toEqual(body);
    });

    it.each(['__proto__', 'constructor', 'prototype'])('rejects unsafe object key %s', async (key) => {
        const response = await request(app())
            .post('/')
            .set('Content-Type', 'application/json')
            .send(`{"nested":[{"${key}":{"polluted":true}}]}`);
        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Invalid request body field');
        expect(Object.prototype).not.toHaveProperty('polluted');
    });

    it('rejects excessive nesting instead of recursing or modifying data', async () => {
        let body: unknown = { value: 'preserved' };
        for (let depth = 0; depth < 40; depth++) body = { nested: body };
        const response = await request(app())
            .post('/')
            .send(body as object);
        expect(response.status).toBe(400);
        expect(response.body.error).toContain('maximum depth');
    });
});
