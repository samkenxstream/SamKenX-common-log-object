var strftime = require('prettydate').strftime;
var urlParse = require('url').parse;

module.exports = function generateCommonLog(request, response, options)
{
    if (!request || !response) return '';

    options = options || {};


    var protocol = 'HTTP/' + request.httpVersion;
    var payload_len = (response._data && response._data.length) || request.headers['content-length'];
    payload_len = payload_len || '-';

    var UA = request.headers['user-agent'] || '-';
    var referer = request.headers['referer'] || '-';
    var tstamp = (response._time && new Date(response._time)) || (request.start && new Date(request.start));
    tstamp = tstamp || new Date();

    var accepts = request.headers['accept'] || '-';
    var elapsed = (response._time && (Date.now() - response._time)) || request.latency
    elapsed = (elapsed && elapsed + ' ms') || '';

    var remote;

    if (options.ipHeader && request.headers[options.ipHeader])
    {
        remote = request.headers[options.ipHeader];
    }
    else if (request.socket)
    {
        remote = request.socket.remoteAddress;
    }
    else if (request.remoteAddress)
    {
        remote = request.remoteAddress;
    }

    remote = remote || '';


    if(options.emitJSON){

        const _headers = {
            req: [        
                'x-forwarded-for',
                'request-id',
                'from',
                'connection',
                'cf-ray',
                'cf-connecting-ip',
                'user-agent',
                'content-length',
                'content-type',
                'referer',
                'accept',
            ],
            res: [
                'content-type',
                'location',
                'content-length'
            ]
        }

        var event = {};

        event['@timestamp'] = tstamp;
        event.remoteAddress = remote;
        event.method = request.method;
        var fullURL = request.headers.host + request.url;
        event.latency = elapsed;
        event.url = fullURL
        parsedURL = urlParse(fullURL);
        if(parsedURL.query){
            event.qs=parsedURL.query;
        }

        event.req = {};

        event.req.httpVersion = request.httpVersion;
        event.req.headers = {};
        event.res = {};
        event.res.headers = {};
            _headers.req.forEach((k)=>{
                if(request.headers[k]){
                    event.req.headers[k] = request.headers[k]
                }
            })
            _headers.res.forEach((k)=>{
                let v = response.get(k)
                if(v){
                    event.req.headers[k] = v;
                }
            })
        event.res.statusCode = response.statusCode;
        if(response.statusCode == 500){
            event.req.body = request.body;
        }
        return event;
    }


    var fields = [
        remote.replace('::ffff:', ''), // client ip
        '-',  // RFC 1413, never used
        '-',   // userid as determined by http auth
        '[' + strftime(tstamp, '%d/%b/%Y:%H:%M:%S %z') + ']', // time
        '"' + [request.method, request.url, protocol].join(' ') + '"',
        response.statusCode,
        payload_len,
        '"' + referer + '"',
        '"' + UA + '"',
        '"' + accepts + '"',
        elapsed,
    ];

    return fields.join(' ');
};
