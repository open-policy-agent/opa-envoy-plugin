package cls.authz

import data.cls.common
import input.attributes.request.http as http_request
import input.policies as policies
import input.payload as payload
import input.metadata as metadata

filter[[effect, policy_id, statement_id, condition_result]] {
    some policy_id, statement_id

    effect := policies[policy_id].statements[statement_id].effect
    common.checkAuthority(policies[policy_id], payload)
    policies[policy_id].statements[statement_id].methods[_] == http_request.method
    path_regex := policies[policy_id].statements[statement_id].path_regex
    regex.match(path_regex, http_request.path)
    conditions := policies[policy_id].statements[statement_id].conditions
    cond_results := [x | some operation, key
		val := conditions[operation][key]
        x := common.evaluateCondition(operation, metadata, key, val)
        ]
    condition_result := common.aggregateConditions(cond_results)    
}

allow {
	filter[["allow", _, _, true]]
} else = false

deny {
	filter[["deny", _, _, true]]
} else = false

authorized {
	allow
	not deny
} else = false

#./opa_envoy_linux_amd64 run --server --addr=0.0.0.0:8181 --diagnostic-addr=0.0.0.0:8282 --set=plugins.envoy_ext_authz_grpc.addr=:9191 --set=plugins.envoy_ext_authz_grpc.query=data.cls.authz.authorized --set=decision_logs.console=true --set=log-level=debug --ignore=.* --watch --ready-timeout=3 ./vinh-test/authz.rego ./vinh-test/common.rego