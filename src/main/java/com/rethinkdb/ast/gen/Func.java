// Autogenerated by convert_protofile.py on 2015-05-07.
// Do not edit this file directly.
// The template for this file is located at:
// ../../../../../../../../templates/gen/Func.java
package com.rethinkdb.ast.gen;

import com.rethinkdb.ast.helper.Arguments;
import com.rethinkdb.ast.helper.OptArgs;
import com.rethinkdb.ast.RqlAst;
import com.rethinkdb.proto.TermType;
import java.util.*;


import com.rethinkdb.model.RqlFunction2;
import com.rethinkdb.model.RqlFunction;
import com.rethinkdb.model.RqlLambda;
import com.rethinkdb.ast.RqlUtil;


public class Func extends RqlQuery {


    public Func(RqlLambda function) {
        super(null, TermType.FUNC, null, null);
        if (function instanceof RqlFunction) {
            super.init(
                null,
                Arguments.make(
                    new MakeArray(new Arguments(1), null),
                    RqlUtil.toRqlAst(
                        ((RqlFunction)function).apply(
                            new Var(new Arguments(1), null)))
                ),
                null
            );
        }
        else {
            super.init(
                null,
                Arguments.make(
                    new MakeArray(Arguments.make(1, 2), null),
                    RqlUtil.toRqlAst(
                        ((RqlFunction2)function).apply(
                            new Var(new Arguments(1), null),
                            new Var(new Arguments(2), null)))
                ),
                null
            );
        }
    }



}
