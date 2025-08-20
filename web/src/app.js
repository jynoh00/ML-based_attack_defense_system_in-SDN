const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');

// ROUTER SETTING
const indexRouter = require('./routes/index');
const moreRouter = require('./routes/more');
const errorRouter = require('./routes/error');

const app = express();

app.set('views', path.join(__dirname, '../views'));
app.set('view engine', 'ejs');

// MIDLEWARE SETTING
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.json());

app.use('/', indexRouter);
app.use('/more', moreRouter);
app.use(errorRouter);

module.exports = app;