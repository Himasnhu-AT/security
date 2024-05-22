import { ParameterDeclaration } from "typescript";
import { HasDecorators } from "typescript";
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
async signUp(body: SignUpDto) {
  const { name, email, password, userName } = body;
  // No validation decorators on parameters
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
  if (isMethodDeclaration(node)) {
    const methodName = node.name.getText();
    if (methodName === "signUp") {
      const parameters = node.parameters;
      if (
        !parameters.some((param: ParameterDeclaration) => HasDecorators(param))
      ) {
        securityIssues.push("Missing validation in signUp method parameters.");
      }
    }
  }

  forEachChild(node, analyzeNode);
  forEachChild(node, analyzeNode);
};

forEachChild(sourceFile, analyzeNode);

if (securityIssues.length > 0) {
  console.log("Security issues found:");
  securityIssues.forEach((issue) => console.log(`- ${issue}`));
} else {
  console.log("No significant security issues found.");
}
