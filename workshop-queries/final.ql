/**
 * @name UAF-Tutorial-Final-Query
 * @kind path-problem
 * @problem.severity warning
 * @id cpp/example/uaf
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import DataFlow::PathGraph

class Config extends DataFlow::Configuration {
    Config() { this = "Config: name doesn't matter"}

    override predicate isSource(DataFlow::Node arg) {
        exists( FunctionCall call|
            call.getArgument(0) = arg.asDefiningArgument() and
            call.getTarget().hasGlobalOrStdName("free")

        )
    }

    override predicate isSink(DataFlow::Node sink) {
        dereferenced(sink.asExpr())
    }

    override predicate isBarrier(DataFlow::Node barrier) {
        none()
    }
}

from Config config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Memory is $@ and $@, causing vuln.", source, "freed here", sink, "used here"

