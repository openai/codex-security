function testOnlyQuery(req) {
  const sql = "SELECT * FROM test_rows WHERE name = '" + req.query.q + "'";
  return sql;
}

module.exports = { testOnlyQuery };
