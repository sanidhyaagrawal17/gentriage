const { MongoClient } = require('mongodb');

const MONGO = process.env.MONGO || 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME || 'gentriage';

async function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function run() {
  const client = new MongoClient(MONGO);
  await client.connect();
  const db = client.db(DB_NAME);
  const ingests = db.collection('ingests');
  const alerts = db.collection('alerts');

  console.log('Worker started: polling ingests...');
  while (true) {
    const job = await ingests.findOneAndDelete({});
    if (job.value) {
      const item = job.value;
      console.log('Processing ingest', item._id);
      // simulate analysis
      await sleep(1200);
      const risk = Math.floor(60 + Math.random() * 40);
      const status = risk > 90 ? 'Critical' : (risk > 75 ? 'High Risk' : 'Medium');
      const alert = {
        createdAt: new Date(),
        source: item.source || item.name || 'upload',
        id: `ACCT-${Math.floor(Math.random()*9000)+1000}`,
        status,
        risk,
        anomaly: (Math.random()*0.4 + 0.6).toFixed(2),
        tags: ['Auto-detected'],
        explanation: 'Auto analysis summary: simulated'
      };
      await alerts.insertOne(alert);
      console.log('Inserted alert', alert.id);
    } else {
      await sleep(1500);
    }
  }
}

run().catch((e) => { console.error(e); process.exit(1); });
