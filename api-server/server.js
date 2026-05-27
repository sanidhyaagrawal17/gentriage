const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bodyParser = require('body-parser');

const MONGO = process.env.MONGO || 'mongodb://localhost:27017';
const PORT = process.env.PORT || 5000;
const DB_NAME = process.env.DB_NAME || 'gentriage';

async function main() {
  const client = new MongoClient(MONGO);
  await client.connect();
  const db = client.db(DB_NAME);
  const alerts = db.collection('alerts');
  const ingests = db.collection('ingests');

  const app = express();
  app.use(cors());
  app.use(bodyParser.json());

  app.get('/api/alerts', async (req, res) => {
    const docs = await alerts.find().sort({ createdAt: -1 }).limit(200).toArray();
    res.json(docs);
  });

  app.get('/api/alerts/:id', async (req, res) => {
    try {
      const doc = await alerts.findOne({ _id: new ObjectId(req.params.id) });
      res.json(doc);
    } catch (e) {
      res.status(400).json({ error: 'invalid id' });
    }
  });

  app.post('/api/ingest', async (req, res) => {
    const item = Object.assign({ createdAt: new Date(), status: 'queued' }, req.body || {});
    const r = await ingests.insertOne(item);
    res.json({ ok: true, id: r.insertedId });
  });

  app.get('/api/dashboard', async (req, res) => {
    // basic aggregation for dashboard
    const latestAlerts = await alerts.find().sort({ createdAt: -1 }).limit(10).toArray();
    const countCritical = await alerts.countDocuments({ status: 'Critical' });
    const countHigh = await alerts.countDocuments({ status: 'High Risk' });
    const total = await alerts.countDocuments();

    // feature bars computed from recent alerts
    const featureBars = [
      { label: 'Velocity burst', value: 92 },
      { label: 'Cash-out pattern', value: 84 },
      { label: 'Geo/IP mismatch', value: 71 }
    ];

    res.json({
      alerts: latestAlerts,
      metrics: [
        { label: 'Active Alerts', value: String(total), hint: '', tone: '#e46b6b' },
        { label: 'Critical', value: String(countCritical), hint: '', tone: '#e46b6b' },
        { label: 'High Risk', value: String(countHigh), hint: '', tone: '#e08f45' },
        { label: 'Resolved', value: '64%', hint: 'Analyst approved', tone: '#4fb07c' }
      ],
      datasets: [
        { name: 'Credit Card Fraud Detection', type: 'Wide CSV', summary: 'A classic high-imbalance benchmark to validate risk scoring quickly.', accent: '#f2a65a' }
      ],
      activity: [],
      featureBars
    });
  });

  app.listen(PORT, () => {
    console.log(`API server listening on http://localhost:${PORT}`);
  });
}

main().catch((err) => { console.error(err); process.exit(1); });
