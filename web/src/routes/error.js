const express = require('express');
const router = express.Router();

router.use((req, res) => {
    console.log('error.js Router running : error.ejs render');
    res.status(404).render('error', {
        statusCode: 404,
        message: '페이지를 찾을 수 없습니다',
    });
});

router.use((req, res) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
    });
});

module.exports = router;