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
const token = Math.random().toString(36).substring(2);
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
    if (functionName.includes("Math.random")) {
      securityIssues.push("Insecure token generation found using Math.random.");
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
