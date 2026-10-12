// Run only as a preload in the migration CLI test process. Commit a real Mongo
// update after the migration read/round-trip but immediately before its write.
const { Collection } = require('mongodb');
const updateOne = Collection.prototype.updateOne;
Collection.prototype.updateOne = async function (filter, update, options) {
  if (this.collectionName === 'whistleblower_reports' && update.$set?.encryptedNarrative) {
    const competing = JSON.parse(process.env.NARRATIVE_MIGRATION_COMPETING_WRITE);
    await updateOne.call(this, { _id: filter._id }, { $set: competing });
  }
  return updateOne.call(this, filter, update, options);
};
