import * as ts from "typescript";

function findSecurityIssues(sourceCode: string) {
  const sourceFile = ts.createSourceFile(
    "code.ts",
    sourceCode,
    ts.ScriptTarget.ES2015,
    true
  );

  function analyzeNode(node: ts.Node) {
    // Check for SQL injection vulnerabilities
    if (ts.isTemplateExpression(node) || ts.isStringLiteral(node)) {
      const text = node.getText(sourceFile);
      console.log(text);
      if (
        text.includes("SELECT") ||
        text.includes("INSERT") ||
        text.includes("UPDATE") ||
        text.includes("DELETE")
      ) {
        console.log(
          "Potential SQL injection detected: Use parameterized queries to prevent SQL injection."
        );
      }
    }

    // Check for command injection vulnerabilities
    if (ts.isCallExpression(node)) {
      const expression = node.expression;
      if (ts.isIdentifier(expression) && expression.text === "exec") {
        console.log(
          "Potential command injection detected: Avoid using exec() with user input."
        );
      }
    }

    // Check for XSS vulnerabilities
    if (ts.isPropertyAccessExpression(node) && node.name.text === "innerHTML") {
      console.log(
        "Potential XSS detected: Avoid using innerHTML with user input."
      );
    }

    // Check for insecure use of dangerous functions like eval()
    if (ts.isCallExpression(node)) {
      const expression = node.expression;
      if (expression.kind === ts.SyntaxKind.Identifier) {
        const functionName = (expression as ts.Identifier).text;
        if (functionName === "eval") {
          console.log(
            "Security issue detected: eval() can lead to code injection vulnerabilities."
          );
        }
      }
    }

    // Check for variables with any type
    if (ts.isVariableDeclaration(node)) {
      const type = node.type;
      if (type && type.kind === ts.SyntaxKind.AnyKeyword) {
        console.log(
          "Security flaw detected: Variables should not have type any as it bypasses TypeScript type checking."
        );
      }
    }

    // Check for improper error handling that can leak sensitive information
    if (ts.isTryStatement(node)) {
      const catchClause = node.catchClause;
      if (catchClause && catchClause.variableDeclaration) {
        const catchBlock = catchClause.block;
        if (
          catchBlock.statements.some((statement) =>
            ts.isThrowStatement(statement)
          )
        ) {
          console.log(
            "Security issue detected: Throwing errors without sanitization can leak sensitive information."
          );
        }
      }
    }

    // Check for CSRF vulnerabilities
    if (
      ts.isCallExpression(node) &&
      node.arguments.some((arg) => ts.isIdentifier(arg) && arg.text === "fetch")
    ) {
      console.log(
        "Potential CSRF detected: Ensure proper CSRF token handling with fetch requests."
      );
    }

    ts.forEachChild(node, analyzeNode);
  }

  analyzeNode(sourceFile);
}

const code = `
  const unsafeQuery = \SELECT * FROM users WHERE username = '\${userInput}'\;
  exec(\rm -rf \${userDirectory}\);
  document.getElementById('content').innerHTML = userInput;
  fetch('/api/transfer', { method: 'POST', body: JSON.stringify({ amount: 1000 }) });

  try {
    var userInputs: any;
    eval('console.log("Running eval with user input: " + userInput)');
  } catch (error) {
    throw error; // This can potentially leak sensitive information
  }
;`;

findSecurityIssues(code);
