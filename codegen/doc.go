// Package codegen owns the Java Card backend for javacard-rpc. Plugin consumes a
// validated pluginapi.Schema and explicit pluginapi.Options, and returns the
// complete ordered Gradle package in memory. Parsing, common validation, target
// selection, option defaults and filesystem publication belong to the facade.
// The root repository tag versions this backend and the Java runtime together.
package codegen
