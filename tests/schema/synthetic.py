"""Fifteen satisfiable 2020-12 schemas spanning generation-relevant vocabulary."""

SCHEMAS = {
    "prefix-items": {
        "type": "array",
        "prefixItems": [{"const": "tag"}, {"type": "integer"}],
        "items": False,
        "minItems": 2,
    },
    "recursive-defs": {
        "$defs": {
            "node": {
                "type": "object",
                "properties": {
                    "label": {"type": "string", "maxLength": 4},
                    "next": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/node"}]},
                },
                "required": ["label"],
                "additionalProperties": False,
            }
        },
        "$ref": "#/$defs/node",
    },
    "dependent-required": {
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "boolean"}},
        "dependentRequired": {"a": ["b"]},
        "required": ["a"],
        "additionalProperties": False,
    },
    "dependent-schemas": {
        "type": "object",
        "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
        "dependentRequired": {"a": ["b"]},
        "dependentSchemas": {"a": {"properties": {"b": {"minimum": 1}}}},
        "required": ["a"],
        "additionalProperties": False,
    },
    "one-of": {
        "oneOf": [{"type": "integer", "minimum": 1}, {"type": "string", "pattern": "^[a-z]{1,4}$"}]
    },
    "any-of": {"anyOf": [{"type": "integer", "maximum": 0}, {"enum": [0, 1, "yes"]}]},
    "all-of": {"allOf": [{"type": "integer", "minimum": -3}, {"maximum": 3}]},
    "conditional": {
        "type": "object",
        "properties": {"kind": {"enum": ["a", "b"]}, "value": {}},
        "required": ["kind", "value"],
        "additionalProperties": False,
        "if": {"properties": {"kind": {"const": "a"}}},
        "then": {"properties": {"value": {"type": "integer"}}},
        "else": {"properties": {"value": {"type": "boolean"}}},
    },
    "const": {"const": {"$ref": "data", "prefixItems": [1], "$defs": {"x": "data"}}},
    "enum": {"enum": [None, 7, "seven", {"value": [True, False]}]},
    "contains": {
        "type": "array",
        "items": {"type": "integer"},
        "maxItems": 3,
        "contains": {"minimum": 0},
        "minContains": 1,
        "maxContains": 2,
    },
    "property-names": {
        "type": "object",
        "propertyNames": {"pattern": "^[a-z]{1,3}$"},
        "additionalProperties": {"type": "integer"},
        "maxProperties": 2,
    },
    "anchor": {
        "$defs": {"value": {"$anchor": "value", "type": "string", "maxLength": 4}},
        "type": "object",
        "properties": {"value": {"$ref": "#value"}},
        "required": ["value"],
        "additionalProperties": False,
    },
    "nested": {
        "type": "object",
        "properties": {
            "rows": {
                "type": "array",
                "maxItems": 2,
                "items": {
                    "type": "object",
                    "properties": {
                        "tags": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": 3},
                            "maxItems": 2,
                        }
                    },
                    "additionalProperties": False,
                },
            }
        },
        "required": ["rows"],
        "additionalProperties": False,
        "unevaluatedProperties": False,
    },
    "formats": {
        "type": "object",
        "properties": {
            "email": {"type": "string", "format": "email"},
            "timestamp": {"type": "string", "format": "date-time"},
            "url": {"type": "string", "format": "uri"},
        },
        "required": ["email", "timestamp", "url"],
        "additionalProperties": False,
    },
}

for schema in SCHEMAS.values():
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
