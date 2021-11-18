package cls.common

executeCondition(operation, in, stored) {
    operation == "equals"
    in == stored
}

executeCondition(operation, in, stored) {
    operation == "notEquals"
    in != stored
}

evaluateCondition(operation, metadata, key, stored) = true {
    in := metadata[key]
	executeCondition(operation, in, stored)
} else = false

aggregateConditions(c) = false {
	count(c) > 0
    c[_] == false
} else = true

checkAuthority(policy, payload) = true {
    roles := payload.realm_access.roles
    count(roles) > 0
    policy.roles[_] == roles[_]
} else = true {
    policy.members[_] == payload.preferred_username
} else = false