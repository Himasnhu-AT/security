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
let user = await this.prisma.user.create({
  data: {
    email,
    password, // Storing password in plain text
  },
});
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
    if (functionName.includes("this.prisma.user.create")) {
      const argument = node.arguments[0].getText();
      if (argument.includes("password")) {
        securityIssues.push(
          "Plain text password storage detected in user creation method."
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
