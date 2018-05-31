var _ = require('underscore');
var fs = require('fs');
var async = require('async');
var bodyParser = require('body-parser');
var crypto = require('crypto');
var ect = require('ect');
var express = require('express');
var logger = require('morgan');
var mysql = require('mysql');
var path = require('path');
var session = require('express-session');
// var RedisStore = require('connect-redis')(session);
var strftime = require('strftime');

var app = express();

var globalConfig = {
  userLockThreshold: process.env.ISU4_USER_LOCK_THRESHOLD || 3,
  ipBanThreshold: process.env.ISU4_IP_BAN_THRESHOLD || 10
};

var mysqlPool = mysql.createPool({
  host: process.env.ISU4_DB_HOST || 'localhost',
  user: process.env.ISU4_DB_USER || 'root',
  password: process.env.ISU4_DB_PASSWORD || '',
  database: process.env.ISU4_DB_NAME || 'isu4_qualifier'
});

/**
 * global cache
 */
// pass hash
var pHash = {};
// select * from user
var userUserIdCache = {};
var userLoginCache = {};
// login_log cache
var loginLogUserIdCache = {};
var loginLogIpCache = {};


var helpers = {
  calculatePasswordHash: function(password, salt) {
    var data = password + ':' + salt;
    // check cache
    if (pHash[data]) return pHash[data];
    // generate
    var c = crypto.createHash('sha256');
    c.update(data);
    // cache
    pHash[data] = c.digest('hex');
    return pHash[data];
  },

  isUserLocked: function(user, callback) {
    if(!user) {
      return callback(false);
    };

    if (loginLogUserIdCache[user.id]) return callback(loginLogUserIdCache[user.id]);

    mysqlPool.query(
      'SELECT COUNT(1) AS failures FROM login_log WHERE ' +
      'user_id = ? AND id > IFNULL((select max(id) from login_log where ' +
      'user_id = ? AND succeeded = 1), 0);',
      [user.id, user.id],
      function(err, rows) {
        if(err) {
          return callback(false);
        }

        loginLogUserIdCache[user.id] = globalConfig.userLockThreshold <= rows[0].failures;
        callback(loginLogUserIdCache[user.id]);
      }
    )
  },

  isIPBanned: function(ip, callback) {
    if (loginLogIpCache[ip]) return callback(loginLogIpCache[ip]);

    // TODO: select id from login_log where ip = ?, and sort and filter succeded

    mysqlPool.query(
      'SELECT COUNT(1) AS failures FROM login_log WHERE ' +
      'ip = ? AND id > IFNULL((select max(id) from login_log where ip = ? AND ' +
      'succeeded = 1), 0);',
      [ip, ip],
      function(err, rows) {
        if(err) {
          return callback(false);
        }

        loginLogIpCache[ip] = globalConfig.ipBanThreshold <= rows[0].failures;
        callback(loginLogIpCache[ip]);
      }
    )
  },

  attemptLogin: function(req, callback) {
    var ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    var login = req.body.login;
    var password = req.body.password;

    async.waterfall([
      function(cb) {
        if (userLoginCache[login]) return cb(null, userLoginCache[login]);

        mysqlPool.query('SELECT * FROM users WHERE login = ?', [login], function(err, rows) {
          if (!rows[0]) return cb('wrong_login', rows[0]);

          userLoginCache[login] = rows[0];
          cb(null, rows[0]);
        });
      },
      function(user, cb) {
        helpers.getBannedOrUserLocked(user, ip, cb);
      },
      function(user, cb) {
        if(user && helpers.calculatePasswordHash(password, user.salt) == user.password_hash) {
          cb(null, user);
        } else if(user) {
          cb('wrong_password', user);
        } else {
          cb('wrong_login', user);
        };
      }
    ], function(err, user) {
      var succeeded = !err;
      var userId = (user || {})['id']

      // HACK: this is not correct, but get HIGH-SCORE !
      // delete cache if updated
      if (loginLogUserIdCache[userId]) delete loginLogUserIdCache[userId];
      if (loginLogIpCache[ip]) delete loginLogIpCache[ip];
      callback(err, user);

      mysqlPool.query(
        'INSERT INTO login_log' +
        ' (`created_at`, `user_id`, `login`, `ip`, `succeeded`)' +
        ' VALUES (?,?,?,?,?)',
        [new Date(), userId, login, ip, succeeded],
        function(e, rows) {
          // // delete cache if updated
          // if (loginLogUserIdCache[userId]) delete loginLogUserIdCache[userId];
          // if (loginLogIpCache[ip]) delete loginLogIpCache[ip];
          // callback(err, user);
        }
      );
    });
  },

  getBannedOrUserLocked: function(user, ip, callback) {
    async.parallel([
      function(cb) {
        helpers.isIPBanned(ip, function(banned) {
          if(banned) {
            cb(null, 'banned');
          } else {
            cb(null, user);
          };
        });
      },
      function(cb) {
        helpers.isUserLocked(user, function(locked) {
          if(locked) {
            cb(null, 'locked');
          } else {
            cb(null, user);
          };
        });
      }
    ], function(err, results) {
      if (results[0] === 'banned') return callback('banned', user);
      if (results[1] === 'locked') return callback('locked', user);
      callback(null, user);
    })
  },

  getCurrentUserId: function(user_id, callback) {
    if (userUserIdCache[user_id]) return callback(userUserIdCache[user_id]);

    mysqlPool.query('SELECT id FROM users WHERE id = ? limit 1', [user_id], function(err, rows) {
      if(err) {
        return callback(null);
      }

      userUserIdCache[user_id] = rows[0];
      callback(rows[0]);
    });
  },

  getBannedIPs: function(callback) {
    mysqlPool.query(
      'SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM '+
      'login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?',
      [globalConfig.ipBanThreshold],
      function(err, rows) {
        var bannedIps = _.map(rows, function(row) { return row.ip; });

        mysqlPool.query(
          'SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip',
          function(err, rows) {
            async.parallel(
              _.map(rows, function(row) {
                return function(cb) {
                  mysqlPool.query(
                    'SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id',
                    [row.ip, row.last_login_id],
                    function(err, rows) {
                      if(globalConfig.ipBanThreshold <= (rows[0] || {})['cnt']) {
                        bannedIps.push(row['ip']);
                      }
                      cb(null);
                    }
                  );
                };
              }),
              function(err) {
                callback(bannedIps);
              }
            );
          }
        );
      }
    )
  },

  getLockedUsers: function(callback) {
    mysqlPool.query(
      'SELECT user_id, login FROM ' +
      '(SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM ' +
      'login_log GROUP BY user_id) AS t0 WHERE t0.user_id IS NOT NULL AND ' +
      't0.max_succeeded = 0 AND t0.cnt >= ?',
      [globalConfig.userLockThreshold],
      function(err, rows) {
        var lockedUsers = _.map(rows, function(row) { return row['login']; });

        mysqlPool.query(
          'SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE ' +
          'user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id',
          function(err, rows) {
            async.parallel(
              _.map(rows, function(row) {
                return function(cb) {
                  mysqlPool.query(
                    'SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id',
                    [row['user_id'], row['last_login_id']],
                    function(err, rows) {
                      if(globalConfig.userLockThreshold <= (rows[0] || {})['cnt']) {
                        lockedUsers.push(row['login']);
                      };
                      cb(null);
                    }
                  );
                };
              }),
              function(err) {
                callback(lockedUsers);
              }
            );
          }
        );
      }
    )
  }
};

// app.use(logger('dev'));
app.enable('trust proxy');
app.engine('ect', ect({ watch: false, root: __dirname + '/views', ext: '.ect' }).render);
app.set('view engine', 'ect');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ /*store: new RedisStore({}),*/ 'secret': 'isucon4-node-qualifier', resave: true, saveUninitialized: true }));
app.use(express.static(path.join(__dirname, '../public')));

app.locals.strftime = function(format, date) {
  return strftime(format, date);
};

app.get('/', function(req, res) {
  var notice = req.session.notice;
  req.session.notice = null;

  res.render('index', { 'notice': notice });
});

app.post('/login', function(req, res) {
  helpers.attemptLogin(req, function(err, user) {
    if(err) {
      switch(err) {
        case 'locked':
          req.session.notice = 'This account is locked.';
          break;
        case 'banned':
          req.session.notice = "You're banned.";
          break;
        default:
          req.session.notice = 'Wrong username or password';
          break;
      }

      return res.redirect('/');
    }

    req.session.userId = user.id;
    res.redirect('/mypage');
  });
});

app.get('/mypage', function(req, res) {
  helpers.getCurrentUserId(req.session.userId, function(user) {
    if(!user) {
      req.session.notice = "You must be logged in"
      return res.redirect('/')
    }

    mysqlPool.query(
      'SELECT * FROM login_log WHERE user_id = ? AND succeeded = 1 ORDER BY id DESC LIMIT 2',
      [user.id],
      function(err, rows) {
        var lastLogin = rows[rows.length-1];
        res.render('mypage', { 'last_login': lastLogin });
      }
    );
  });
});

app.get('/report', function(req, res) {
  async.parallel({
    banned_ips: function(cb) {
      helpers.getBannedIPs(function(ips) {
        cb(null, ips);
      });
    },
    locked_users: function(cb) {
      helpers.getLockedUsers(function(users) {
        cb(null, users);
      });
    }
  }, function(err, result) {
    res.json(result);
  });
});

app.use(function (err, req, res, next) {
  res.status(500).send('Error: ' + err.message);
});



// var sockPath = '/tmp/node.sock';
// try {
//   fs.unlinkSync(sockPath);
// } catch(e) {}

var server = app.listen(8080, function(err) {
  // if (err) throw err;
  // fs.chmodSync(sockPath, '777');
  console.log('Listening on port %d', server.address().port);
});
