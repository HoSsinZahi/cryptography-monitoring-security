const { createApp } = require('./app');
const { config } = require('./config');

const { app } = createApp();
const port = Number(process.env.PORT || 3000);

if (require.main === module) {
  app.listen(port, () => {
    console.log(`${config.appName} listening on port ${port}`);
  });
}

module.exports = app;
