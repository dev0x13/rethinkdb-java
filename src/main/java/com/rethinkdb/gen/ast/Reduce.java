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



public class Reduce extends ReqlExpr {


    public Reduce(Object arg) {
        this(new Arguments(arg), null);
    }
    public Reduce(Arguments args){
        this(args, null);
    }
    public Reduce(Arguments args, OptArgs optargs) {
        this(TermType.REDUCE, args, optargs);
    }
    protected Reduce(TermType termType, Arguments args, OptArgs optargs){
        super(termType, args, optargs);
    }
}
