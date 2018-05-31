var cluster = require('cluster');
var numCPUs = require('os').cpus().length;

// if (cluster.isMaster) {
//   for (var i = 0; i < 3; i++) {
//     // Create a worker
//     cluster.fork();
//   }
// } else {
//   require('./slave');
// }

require('./slave');
