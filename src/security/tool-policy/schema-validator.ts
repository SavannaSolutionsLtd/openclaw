/**
 * Schema Validator for Tool Calls
 *
 * Validates tool call parameters against defined schemas to prevent
 * injection attacks and ensure type safety.
 *
 * @module security/tool-policy/schema-validator
 */

/**
 * Property type definition
 */
export type PropertyType = "string" | "number" | "boolean" | "object" | "array" | "null" | "any";

/**
 * Property schema definition
 */
export interface PropertySchema {
  type: PropertyType | PropertyType[];
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  items?: PropertySchema;
  properties?: Record<string, PropertySchema>;
  additionalProperties?: boolean;
  description?: string;
}

/**
 * Tool schema definition
 */
export interface ToolSchema {
  name: string;
  description?: string;
  properties: Record<string, PropertySchema>;
  required?: string[];
  additionalProperties?: boolean;
}

/**
 * Validation error
 */
export class SchemaValidationError extends Error {
  public readonly path: string;
  public readonly expected: string;
  public readonly actual: string;
  public readonly toolName: string;

  constructor(message: string, toolName: string, path: string, expected: string, actual: string) {
    super(message);
    this.name = "SchemaValidationError";
    this.toolName = toolName;
    this.path = path;
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors: SchemaValidationError[];
  warnings: string[];
  sanitizedParams?: Record<string, unknown>;
}

/**
 * Get the type of a value
 */
function getValueType(value: unknown): PropertyType {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  return typeof value as PropertyType;
}

/**
 * Check if a value matches a type
 */
function matchesType(value: unknown, type: PropertyType | PropertyType[]): boolean {
  const actualType = getValueType(value);

  if (Array.isArray(type)) {
    return type.includes(actualType) || type.includes("any");
  }

  return type === actualType || type === "any";
}

/**
 * Validate a value against a property schema
 */
function validateProperty(
  value: unknown,
  schema: PropertySchema,
  path: string,
  toolName: string,
  errors: SchemaValidationError[],
  warnings: string[],
): unknown {
  // Check type
  if (!matchesType(value, schema.type)) {
    const expectedTypes = Array.isArray(schema.type) ? schema.type.join(" | ") : schema.type;
    errors.push(
      new SchemaValidationError(
        `Invalid type at ${path}: expected ${expectedTypes}, got ${getValueType(value)}`,
        toolName,
        path,
        expectedTypes,
        getValueType(value),
      ),
    );
    return value;
  }

  // String validations
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(
        new SchemaValidationError(
          `String too short at ${path}: minimum ${schema.minLength}, got ${value.length}`,
          toolName,
          path,
          `minLength ${schema.minLength}`,
          `length ${value.length}`,
        ),
      );
    }

    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push(
        new SchemaValidationError(
          `String too long at ${path}: maximum ${schema.maxLength}, got ${value.length}`,
          toolName,
          path,
          `maxLength ${schema.maxLength}`,
          `length ${value.length}`,
        ),
      );
    }

    if (schema.pattern && !schema.pattern.test(value)) {
      errors.push(
        new SchemaValidationError(
          `String does not match pattern at ${path}`,
          toolName,
          path,
          `pattern ${schema.pattern.source}`,
          value,
        ),
      );
    }

    if (schema.enum && !schema.enum.includes(value)) {
      errors.push(
        new SchemaValidationError(
          `Value not in enum at ${path}: got "${value}", expected one of ${JSON.stringify(schema.enum)}`,
          toolName,
          path,
          `one of ${JSON.stringify(schema.enum)}`,
          value,
        ),
      );
    }
  }

  // Number validations
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push(
        new SchemaValidationError(
          `Number too small at ${path}: minimum ${schema.minimum}, got ${value}`,
          toolName,
          path,
          `minimum ${schema.minimum}`,
          String(value),
        ),
      );
    }

    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push(
        new SchemaValidationError(
          `Number too large at ${path}: maximum ${schema.maximum}, got ${value}`,
          toolName,
          path,
          `maximum ${schema.maximum}`,
          String(value),
        ),
      );
    }

    if (schema.enum && !schema.enum.includes(value)) {
      errors.push(
        new SchemaValidationError(
          `Value not in enum at ${path}: got ${value}, expected one of ${JSON.stringify(schema.enum)}`,
          toolName,
          path,
          `one of ${JSON.stringify(schema.enum)}`,
          String(value),
        ),
      );
    }
  }

  // Array validations
  if (Array.isArray(value)) {
    if (schema.items) {
      return value.map((item, index) =>
        validateProperty(item, schema.items!, `${path}[${index}]`, toolName, errors, warnings),
      );
    }
  }

  // Object validations
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const sanitized: Record<string, unknown> = {};

    // Check required properties
    if (schema.properties) {
      for (const [propName, propSchema] of Object.entries(schema.properties)) {
        if (propSchema.required && !(propName in obj)) {
          errors.push(
            new SchemaValidationError(
              `Missing required property at ${path}.${propName}`,
              toolName,
              `${path}.${propName}`,
              "required",
              "missing",
            ),
          );
        }
      }

      // Validate and sanitize each property
      for (const [propName, propValue] of Object.entries(obj)) {
        const propSchema = schema.properties[propName];

        if (!propSchema) {
          if (schema.additionalProperties === false) {
            errors.push(
              new SchemaValidationError(
                `Unexpected property at ${path}.${propName}`,
                toolName,
                `${path}.${propName}`,
                "no additional properties",
                propName,
              ),
            );
          } else {
            warnings.push(`Unknown property at ${path}.${propName}`);
            // Include unknown properties if additionalProperties is not false
            sanitized[propName] = propValue;
          }
        } else {
          sanitized[propName] = validateProperty(
            propValue,
            propSchema,
            `${path}.${propName}`,
            toolName,
            errors,
            warnings,
          );
        }
      }
    }

    return sanitized;
  }

  return value;
}

/**
 * Validate tool call parameters against a schema
 *
 * @param toolName - Name of the tool
 * @param params - Parameters to validate
 * @param schema - Schema to validate against
 * @returns Validation result
 */
export function validateToolParams(
  toolName: string,
  params: Record<string, unknown>,
  schema: ToolSchema,
): ValidationResult {
  const errors: SchemaValidationError[] = [];
  const warnings: string[] = [];

  // Check required properties
  if (schema.required) {
    for (const requiredProp of schema.required) {
      if (!(requiredProp in params)) {
        errors.push(
          new SchemaValidationError(
            `Missing required parameter: ${requiredProp}`,
            toolName,
            requiredProp,
            "required",
            "missing",
          ),
        );
      }
    }
  }

  // Validate each property
  const sanitizedParams: Record<string, unknown> = {};

  for (const [paramName, paramValue] of Object.entries(params)) {
    const propSchema = schema.properties[paramName];

    if (!propSchema) {
      if (schema.additionalProperties === false) {
        errors.push(
          new SchemaValidationError(
            `Unexpected parameter: ${paramName}`,
            toolName,
            paramName,
            "no additional parameters",
            paramName,
          ),
        );
      } else {
        warnings.push(`Unknown parameter: ${paramName}`);
        sanitizedParams[paramName] = paramValue;
      }
    } else {
      sanitizedParams[paramName] = validateProperty(
        paramValue,
        propSchema,
        paramName,
        toolName,
        errors,
        warnings,
      );
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    sanitizedParams: errors.length === 0 ? sanitizedParams : undefined,
  };
}

/**
 * Tool schema registry
 */
const toolSchemas = new Map<string, ToolSchema>();

/**
 * Register a tool schema
 */
export function registerToolSchema(schema: ToolSchema): void {
  toolSchemas.set(schema.name, schema);
}

/**
 * Get a registered tool schema
 */
export function getToolSchema(toolName: string): ToolSchema | undefined {
  return toolSchemas.get(toolName);
}

/**
 * Validate a tool call against registered schema
 *
 * @param toolName - Name of the tool
 * @param params - Parameters to validate
 * @returns Validation result
 * @throws Error if no schema is registered for the tool
 */
export function validateToolCall(
  toolName: string,
  params: Record<string, unknown>,
): ValidationResult {
  const schema = toolSchemas.get(toolName);

  if (!schema) {
    // No schema registered - allow but warn
    return {
      valid: true,
      errors: [],
      warnings: [`No schema registered for tool: ${toolName}`],
      sanitizedParams: params,
    };
  }

  return validateToolParams(toolName, params, schema);
}

/**
 * Create a validator function for a specific tool
 */
export function createToolValidator(schema: ToolSchema) {
  return (params: Record<string, unknown>): ValidationResult => {
    return validateToolParams(schema.name, params, schema);
  };
}

/**
 * Common tool schemas
 */
export const COMMON_SCHEMAS: Record<string, ToolSchema> = {
  bash: {
    name: "bash",
    description: "Execute a bash command",
    properties: {
      command: {
        type: "string",
        required: true,
        minLength: 1,
        maxLength: 10000,
      },
      timeout: {
        type: "number",
        minimum: 0,
        maximum: 600000, // 10 minutes
      },
      workingDir: {
        type: "string",
        maxLength: 1000,
      },
    },
    required: ["command"],
    additionalProperties: false,
  },

  fileRead: {
    name: "fileRead",
    description: "Read a file",
    properties: {
      path: {
        type: "string",
        required: true,
        minLength: 1,
        maxLength: 4096,
      },
      encoding: {
        type: "string",
        enum: ["utf-8", "utf8", "ascii", "binary", "base64"],
      },
    },
    required: ["path"],
    additionalProperties: false,
  },

  fileWrite: {
    name: "fileWrite",
    description: "Write to a file",
    properties: {
      path: {
        type: "string",
        required: true,
        minLength: 1,
        maxLength: 4096,
      },
      content: {
        type: "string",
        required: true,
        maxLength: 10 * 1024 * 1024, // 10MB
      },
      encoding: {
        type: "string",
        enum: ["utf-8", "utf8", "ascii", "binary", "base64"],
      },
    },
    required: ["path", "content"],
    additionalProperties: false,
  },

  browserNavigate: {
    name: "browserNavigate",
    description: "Navigate browser to a URL",
    properties: {
      url: {
        type: "string",
        required: true,
        minLength: 1,
        maxLength: 2048,
        pattern: /^https?:\/\//,
      },
      waitFor: {
        type: "string",
        enum: ["load", "domcontentloaded", "networkidle"],
      },
    },
    required: ["url"],
    additionalProperties: false,
  },
};

// Register common schemas
for (const schema of Object.values(COMMON_SCHEMAS)) {
  registerToolSchema(schema);
}
