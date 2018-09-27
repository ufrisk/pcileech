// a simple parser for Valve's KeyValue format
// https://developer.valvesoftware.com/wiki/KeyValues
//
// author: Rossen Popov, 2014

var VDF = {
    parse: function(text) {
        if(typeof text != "string") {
            throw new TypeError("VDF.parse: Expecting parameter to be a string");
        }

        lines = text.split("\n");

        var obj = {};
        var stack = [obj];
        var expect_bracket = false;
        var name = "";

        var re_kv = new RegExp(
            '^("((?:\\\\.|[^\\\\"])+)"|([a-z0-9\\-\\_]+))' +
            '([ \t]*(' +
            '"((?:\\\\.|[^\\\\"])*)(")?' +
            '|([a-z0-9\\-\\_]+)' +
            '))?'
            );

        var i = 0, j = lines.length;
        for(; i < j; i++) {
            line = lines[i].trim();

            // skip empty and comment lines
            if( line == "" || line[0] == '/') { continue; }

            // one level deeper
            if( line[0] == "{" ) {
                expect_bracket = false;
                continue;
            }

            if(expect_bracket) {
                throw new SyntaxError("VDF.parse: invalid syntax on line " + (i+1));
            }

            // one level back
            if( line[0] == "}" ) {
                stack.pop();
                continue;
            }

            // parse keyvalue pairs
            while(true) {
                m = re_kv.exec(line);

                if(m === null) {
                    throw new SyntaxError("VDF.parse: invalid syntax on line " + (i+1));
                }

                // qkey = 2
                // key = 3
                // qval = 6
                // vq_end = 7
                // val = 8
                var key = (m[2] !== undefined) ? m[2] : m[3];
                var val = (m[6] !== undefined) ? m[6] : m[8];

                if(val === undefined) {
                    // chain (merge) duplicate key
                    if(stack[stack.length-1][key] === undefined)
                        stack[stack.length-1][key] = {};

                    stack.push(stack[stack.length-1][key]);
                    expect_bracket = true;
                }
                else {
                    if(m[7] === undefined && m[8] === undefined) {
                        line += "\n" + lines[++i];
                        continue;
                    }

                    stack[stack.length-1][key] = val;
                }

                break;
            }
        }

        if(stack.length != 1) throw new SyntaxError("VDF.parse: open parentheses somewhere");

        return obj;
    },

    stringify: function(obj,pretty) {
        if( typeof obj != "object") {
                throw new TypeError("VDF.stringify: First input parameter is not an object");
        }

        pretty = ( typeof pretty == "boolean" && pretty) ? true : false;

        return this._dump(obj,pretty,0);
    },

    _dump: function(obj,pretty,level) {
        if( typeof obj != "object" ) {
            throw new TypeError("VDF.stringify: a key has value of type other than string or object");
        }

        var indent = "\t";
        var buf = "";
        var line_indent = "";


        if(pretty) {
            for(var i = 0; i < level; i++ ) {
                line_indent += indent;
            }
        }

        for(key in obj) {
            if( typeof obj[key] == "object" ) {
                buf += [line_indent, '"', key, '"\n', line_indent, '{\n', this._dump(obj[key],pretty,level+1), line_indent, "}\n"].join('');
            }
            else {
                buf += [line_indent, '"', key, '" "', String(obj[key]), '"\n'].join('');
            }
        }

        return buf;
    }
}
