#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RedX
{
    public sealed class BoxTextException : Exception
    {
        public int Offset { get; }
        public BoxTextException(string msg, int offset) : base($"box text: {msg} (at offset {offset})") { Offset = offset; }
    }

    /// <summary>
    /// Decoder for the Box text the host returns, with the host's JSON mapping (docs/box-grammar.md): string,
    /// number (double), TRUE/FALSE, NELL (null), ;[a, b]: (List&lt;object?&gt;), [ {K[]} = v, {K[ID=2]} = w ]
    /// (Dictionary&lt;string, object?&gt; with keys "K" and "K[ID=2]"), links ({"$link": text}). TTL markers are skipped.
    /// </summary>
    public static class BoxText
    {
        public static object? Decode(string text)
        {
            var r = new Reader(text);
            var v = r.Value(0);
            r.Ttl();
            if (r.Peek() != '\0') r.Fail("unexpected text after the value");
            return v;
        }

        sealed class Reader
        {
            readonly string s; int i;
            static readonly Regex Num = new Regex(@"\G-?\d+(\.\d+)?([eE][+-]?\d+)?");
            static readonly Regex TtlRe = new Regex(@"^\(\s*~?\d+(@\d+)?\s*$");
            static readonly Regex IdAttr = new Regex(@"\G(?i:ID\s*=\s*)?(-?\d+)\s*(?=[,\]])");
            public Reader(string s) { this.s = s; }
            public void Fail(string m) => throw new BoxTextException(m, i);
            char At(int j) => j < s.Length ? s[j] : '\0';
            void Ws()
            {
                for (;;)
                {
                    char c = At(i);
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
                    else if (c == '<' && At(i + 1) == '<')
                    {
                        int e = s.IndexOf(">>", i + 2, StringComparison.Ordinal);
                        if (e < 0) Fail("unterminated comment");
                        i = e + 2;
                    }
                    else return;
                }
            }
            public char Peek() { Ws(); return At(i); }
            bool Eat(char c) { if (Peek() == c) { i++; return true; } return false; }
            void Expect(char c) { if (!Eat(c)) Fail($"expected '{c}'"); }
            static bool IdStart(char c) => c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c > '\u007f';
            static bool IdPart(char c) => IdStart(c) || (c >= '0' && c <= '9') || c == '-';

            string Str()
            {
                int st = i;
                if (At(i) != '"') Fail("expected a string");
                i++;
                for (;;)
                {
                    if (i >= s.Length) Fail("unterminated string");
                    char c = s[i];
                    if (c == '\\') { i += 2; continue; }
                    i++;
                    if (c == '"') break;
                }
                try { return JsonSerializer.Deserialize<string>(s.Substring(st, i - st))!; }
                catch (JsonException) { i = st; Fail("bad string literal"); return ""; }
            }

            string Ident()
            {
                int st = i;
                if (!IdStart(At(i))) Fail("expected an identifier");
                while (i < s.Length && IdPart(s[i])) i++;
                return s.Substring(st, i - st);
            }

            public void Ttl()
            {
                if (Peek() != '(') return;
                int e = s.IndexOf(')', i);
                if (e < 0 || !TtlRe.IsMatch(s.Substring(i, e - i))) Fail("bad TTL marker");
                i = e + 1;
                if (At(i) == '*') i++;
            }

            string LinkText(int start)
            {
                int depth = 0; i = start;
                while (i < s.Length)
                {
                    char c = s[i];
                    if (c == '"') { Str(); continue; }
                    if (c == '[') depth++;
                    else if (c == ']' || c == '}') { if (depth == 0) break; depth--; }
                    else if ((c == ',' || c == ';') && depth == 0) break;
                    i++;
                }
                return s.Substring(start, i - start).Trim();
            }

            public object? Value(int depth)
            {
                if (depth > 200) Fail("nested too deeply");
                char c = Peek();
                if (i >= s.Length) Fail("unexpected end of input");
                if (c == '"')
                {
                    int st = i;
                    var str = Str();
                    int j = i;
                    while (j < s.Length && char.IsWhiteSpace(s[j])) j++;
                    if (At(j) == ':' && IdStart(At(j + 1))) return new Dictionary<string, object?> { ["$link"] = LinkText(st) };
                    return str;
                }
                if (c == ';')
                {
                    i++; Expect('[');
                    var list = new List<object?>();
                    if (!Eat(']'))
                    {
                        do { list.Add(Value(depth + 1)); } while (Eat(','));
                        Expect(']');
                    }
                    Expect(':');
                    return list;
                }
                if (c == '[') { i++; return Body(depth + 1); }
                if (c == '-' || (c >= '0' && c <= '9'))
                {
                    var m = Num.Match(s, i);
                    if (!m.Success) Fail("expected a number");
                    i += m.Length;
                    return double.Parse(m.Value, CultureInfo.InvariantCulture);
                }
                if (IdStart(c))
                {
                    var w = Ident().ToUpperInvariant();
                    if (w == "TRUE") return true;
                    if (w == "FALSE") return false;
                    if (w == "NELL") return null;
                    Fail("unexpected word " + w);
                }
                Fail("unexpected character");
                return null;
            }

            Dictionary<string, object?> Body(int depth)
            {
                var o = new Dictionary<string, object?>();
                while (!Eat(']'))
                {
                    Expect('{');
                    var name = Ident();
                    string? id = null;
                    if (Eat('['))
                    {
                        while (!Eat(']'))
                        {
                            Ws();
                            var m = IdAttr.Match(s, i);
                            if (m.Success && id == null) { id = m.Groups[1].Value; i += m.Length; }
                            else
                                while (i < s.Length && s[i] != ',' && s[i] != ']') { if (s[i] == '"') Str(); else i++; }
                            Eat(',');
                        }
                    }
                    Expect('}'); Expect('=');
                    var v = Value(depth + 1);
                    Ttl();
                    o[id == null ? name : $"{name}[ID={id}]"] = v;
                    if (!Eat(',')) Eat(';');
                }
                return o;
            }
        }
    }
}
