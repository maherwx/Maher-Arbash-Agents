import express from 'express';
const app = express();

async function loadUser(id: string) {
  return db.users.find(id);
}

app.get('/users/:id', async (req, res) => {
  if (!req.params.id) return res.status(400).send('missing');
  try {
    const user = await loadUser(req.params.id);
    return res.json(user);
  } catch (err) {
    throw err;
  }
});
