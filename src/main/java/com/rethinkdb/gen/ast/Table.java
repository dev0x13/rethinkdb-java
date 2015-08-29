// Autogenerated by metajava.py.
// Do not edit this file directly.
// The template for this file is located at:
// ../../../../../../../../templates/AstSubclass.java

package com.rethinkdb.gen.ast;

import com.rethinkdb.gen.proto.TermType;
import com.rethinkdb.gen.model.TopLevel;
import com.rethinkdb.model.Arguments;
import com.rethinkdb.model.OptArgs;
import com.rethinkdb.ast.ReqlAst;



public class Table extends ReqlExpr {


    public Table(Object arg) {
        this(new Arguments(arg), null);
    }
    public Table(Arguments args){
        this(args, null);
    }
    public Table(Arguments args, OptArgs optargs) {
        this(TermType.TABLE, args, optargs);
    }
    protected Table(TermType termType, Arguments args, OptArgs optargs){
        super(termType, args, optargs);
    }
    public Get get(Object expr) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        return new Get(arguments);
    }
    public GetAll getAll(Object... exprs) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAddAll(exprs);
        return new GetAll(arguments);
    }
    public Between between(Object expr, Object exprA) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        arguments.coerceAndAdd(exprA);
        return new Between(arguments);
    }
    public Insert insert(Object expr) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        return new Insert(arguments);
    }
    public Config config() {
        Arguments arguments = new Arguments(this);
        return new Config(arguments);
    }
    public Status status() {
        Arguments arguments = new Arguments(this);
        return new Status(arguments);
    }
    public Wait wait_() {
        Arguments arguments = new Arguments(this);
        return new Wait(arguments);
    }
    public Reconfigure reconfigure() {
        Arguments arguments = new Arguments(this);
        return new Reconfigure(arguments);
    }
    public Rebalance rebalance() {
        Arguments arguments = new Arguments(this);
        return new Rebalance(arguments);
    }
    public Sync sync() {
        Arguments arguments = new Arguments(this);
        return new Sync(arguments);
    }
    public IndexCreate indexCreate(Object expr) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        return new IndexCreate(arguments);
    }
    public IndexCreate indexCreate(Object expr, ReqlFunction1 func1) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        arguments.coerceAndAdd(func1);
        return new IndexCreate(arguments);
    }
    public IndexDrop indexDrop(Object expr) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        return new IndexDrop(arguments);
    }
    public IndexList indexList() {
        Arguments arguments = new Arguments(this);
        return new IndexList(arguments);
    }
    public IndexStatus indexStatus(Object... exprs) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAddAll(exprs);
        return new IndexStatus(arguments);
    }
    public IndexWait indexWait(Object... exprs) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAddAll(exprs);
        return new IndexWait(arguments);
    }
    public IndexRename indexRename(Object expr, Object exprA) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        arguments.coerceAndAdd(exprA);
        return new IndexRename(arguments);
    }
    public GetIntersecting getIntersecting(Object expr) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        return new GetIntersecting(arguments);
    }
    public GetNearest getNearest(Object expr) {
        Arguments arguments = new Arguments(this);
        arguments.coerceAndAdd(expr);
        return new GetNearest(arguments);
    }
}
