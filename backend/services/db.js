function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

function prepare(db, sql) {
  return new Promise((resolve, reject) => {
    const stmt = db.prepare(sql, (err) => {
      if (err) return reject(err);
      resolve(stmt);
    });
  });
}

function runStatement(stmt, params = []) {
  return new Promise((resolve, reject) => {
    stmt.run(params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function finalize(stmt) {
  return new Promise((resolve, reject) => {
    stmt.finalize((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

async function transaction(db, work) {
  if (typeof db.transaction === 'function') {
    return db.transaction(work);
  }

  await run(db, 'BEGIN');
  try {
    const result = await work(db);
    await run(db, 'COMMIT');
    return result;
  } catch (err) {
    await run(db, 'ROLLBACK').catch(() => {});
    throw err;
  }
}

module.exports = {
  all,
  finalize,
  get,
  prepare,
  run,
  runStatement,
  transaction
};
