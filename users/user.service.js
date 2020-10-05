const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const ip = require("ip");
const User = db.User;

module.exports = {
    authenticate,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    audit,
    logout
};

async function authenticate({ username, password }) {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.hash)) {
        let loginTime = new Date();
        let ipAddress = ip.address();
        await User.updateOne({username: username}, {$set: {loginTime: loginTime, ip: ipAddress}})
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id }, config.secret);
        return {
            ...userWithoutHash,
            token,
            ip: ipAddress,
            loginTime: loginTime
        };
    }
}

async function getAll() {
    return await User.find().select('-hash');
}



async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}

async function audit(req) {
    const userId = fetchToken(req).sub;
    const user = await User.findOne({ _id: userId }).select('role');
    if(user.role && user.role.toLowerCase() == 'auditor') {
        return getAll();
    }
    throw new Error("Unauthorized");
}

async function logout(req) {
    const userId = fetchToken(req).sub;
    await User.updateOne({_id: userId}, {$set: {logoutTime: new Date()}});
}

function fetchToken(req) {
    const authHeader = req.headers.authorization;
    var token = authHeader.split(' ')[1];
    return jwt.verify(token, config.secret);
}