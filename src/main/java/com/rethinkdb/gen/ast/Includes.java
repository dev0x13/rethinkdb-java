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



public class Includes extends ReqlExpr {


    public Includes(Object arg) {
        this(new Arguments(arg), null);
    }
    public Includes(Arguments args){
        this(args, null);
    }
    public Includes(Arguments args, OptArgs optargs) {
        this(TermType.INCLUDES, args, optargs);
    }
    protected Includes(TermType termType, Arguments args, OptArgs optargs){
        super(termType, args, optargs);
    }
}
