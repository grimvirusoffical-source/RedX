// Package query implements BoxQL, the RedX query and command language. BoxQL is written in the
// grammar of Box files (braces, [ID=N], =, [...], << comments >>, @> links, (N) TTL markers),
// so one grammar covers data, rules and queries.
//
//	{Get[]} = players:Player[Role = "Admin", Gold > 1000] -> [Name, Gold] @> Guild, Sort = -Gold, Limit = 50
//	{Set[]} = players:Player[ID=7].Level = Level + 1
//	{Add[]} = players:Player[ID=9] = [ {Name[]} = "ann", {Level[]} = 1 ]
//	{Delete[]} = players:Player[Level < 1]
//	{Tx[]} = [ {Require[]} = players:Player[ID=7, Gold >= 5], {Set[]} = players:Player[ID=7].Gold = Gold - 5 ]
//	{Explain[]} = [ {Get[]} = players:Player[Level > 3] ]
//	{Watch[]} = players:Player[Level > 3]
//
// A file holds records (top-level entries such as Player[ID=1]); a record is a box of fields.
// The model is schema-less: a field that does not exist reads as NELL. The language, its
// limits and its authorization rules are specified in docs/boxql.md.
//
// The package talks to storage through link.Store, uses idx indexes when a matching index
// exists, follows @> links (link.Engine) for @> follows and for cascade deletes, and asks a sec
// Authorizer before touching every resource (default deny). It depends on nothing outside the
// standard library and the other redx packages. It is tested against link.MemStore and,
// through the host, against the real engines (POST /v1/bx, see docs/hosting.md).
package query
