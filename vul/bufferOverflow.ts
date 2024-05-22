import {
  Node,
  isIdentifier,
  isCallExpression,
  isMethodDeclaration,
  createSourceFile,
  ScriptTarget,
  SyntaxKind,
  forEachChild,
} from "typescript";

const sourceCode = `
  let bufferOverflow: string[] = [];
  
  function addToBuffer(input: string) {
    bufferOverflow.push(input);
  }
  `;

const sourceFile = createSourceFile(
  "tempFile.ts",
  sourceCode,
  ScriptTarget.Latest,
  true
);

const securityIssues: string[] = [];

const analyzeNode = (node: Node) => {
  if (isCallExpression(node)) {
    const functionName = node.expression.getText();
    if (functionName.includes(".push")) {
      const arrayName = functionName.split(".")[0];
      const arrayDeclaration = sourceFile.forEachChild((child) => {
        if (child.kind === SyntaxKind.VariableStatement) {
          const varStatement = child as any;
          if (
            varStatement.declarationList.declarations[0].name.getText() ===
            arrayName
          ) {
            return varStatement.declarationList.declarations[0];
          }
        }
      });

      if (arrayDeclaration) {
        securityIssues.push(
          `Potential buffer overflow detected in function using array ${arrayName}. Ensure proper length checks.`
        );
      }
    }
  }

  forEachChild(node, analyzeNode);
};

forEachChild(sourceFile, analyzeNode);

if (securityIssues.length > 0) {
  console.log("Security issues found:");
  securityIssues.forEach((issue) => console.log(`- ${issue}`));
} else {
  console.log("No significant security issues found.");
}
