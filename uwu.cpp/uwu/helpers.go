package uwu

// helpers.go - shared parameter extraction and schema builders

func getString(params map[string]interface{}, key string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(params map[string]interface{}, key string) bool {
	if v, ok := params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getInt(params map[string]interface{}, key string) int {
	if v, ok := params[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		case float32:
			return int(n)
		}
	}
	return 0
}

func getFloat(params map[string]interface{}, key string) float64 {
	if v, ok := params[key]; ok {
		switch n := v.(type) {
		case float64:
			return n
		case float32:
			return float64(n)
		case int:
			return float64(n)
		case int64:
			return float64(n)
		}
	}
	return 0
}

func jsonSchema(props map[string]interface{}, required ...string) map[string]interface{} {
	s := map[string]interface{}{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func schemaStr(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "description": desc}
}

func schemaBool(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "boolean", "description": desc}
}

func schemaNum(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "number", "description": desc}
}

func schemaAny(desc string) map[string]interface{} {
	return map[string]interface{}{"description": desc}
}
