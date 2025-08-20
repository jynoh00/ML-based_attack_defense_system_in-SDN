const express = require('express');
const router = express.Router();

router.use((req, res) => {
    console.log('error.js Router running : error.ejs render');
    res.status(404).render('error', {
        statusCode: 404,
        message: `요청하신 페이지가 존재하지 않거나 이동되었을 수 있습니다.<br>홈페이지로 돌아가거나 다른 페이지를 탐색해보세요.`,
    });
});

router.use((err, req, res) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
    });
});

module.exports = router;