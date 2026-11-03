// Usage: npm run db:check  (uses DATABASE_PATH from the environment / .env)
require('dotenv').config({ quiet: true });
const { db, checkIntegrity } = require('../database');

checkIntegrity()
  .then((result) => {
    console.log(JSON.stringify(result, null, 2));
    db.close(() => process.exit(result.ok ? 0 : 1));
  })
  .catch((error) => {
    console.error('Integrity check failed to run:', error.message);
    process.exit(2);
  });
