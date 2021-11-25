function hasSqlInjection(value) {
 
    const sqlMeta = new RegExp('(%27)|(\')|(--)|(%23)|(#)', 'i');
    if (sqlMeta.test(value)) {
        return true;
    }

    const sqlMeta2 = new RegExp('((%3D)|(=))[^\n]*((%27)|(\')|(--)|(%3B)|(;))', 'i');
    if (sqlMeta2.test(value)) {
        return true;
    }

    const sqlTypical = new RegExp('w*((%27)|(\'))((%6F)|o|(%4F))((%72)|r|(%52))', 'i');
    if (sqlTypical.test(value)) {
        return true;
    } 

    const sqlUnion = new RegExp('((%27)|(\'))union', 'i');
    if (sqlUnion.test(value)) {
        return true;
    }
    return false;
}


function middleware(req, res, next) {
 
    let containsSql = false;

    let message = {error: 'Request is detecting SQL Injection'};
   

    if (req.originalUrl !== null && req.originalUrl !== undefined) {
        if (hasSqlInjection(req.originalUrl) === true) {
            containsSql = true;
        }
    }

    if (containsSql === false) {
        let body = req.body;
        if(body !== null && body !== undefined){
            
            if (typeof body !== 'string') {
                body = JSON.stringify(body);
            }
            
            if (hasSqlInjection(body) === true) {
                containsSql = true; 
            }
        }
 
        
        if(containsSql === true){
            res.status(403).json(message);
        }
        else{
            next();
        }

    } else {
        res.status(403).json(message);
    }
}

module.exports = middleware;
