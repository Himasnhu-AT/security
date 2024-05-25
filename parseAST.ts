import * as ts from "typescript";

function parseAST(sourceCode: string) {
  const sourceFile = ts.createSourceFile(
    "code.ts",
    sourceCode,
    ts.ScriptTarget.Latest,
    true
  );

  const variables: { [name: string]: string } = {};
  const functions: { [name: string]: string } = {};
  const interfaces: string[] = [];

  function visit(node: ts.Node) {
    if (ts.isVariableDeclaration(node) && node.type) {
      const variableName = node.name.getText(sourceFile);
      const typeName = node.type.getText(sourceFile);
      variables[variableName] = typeName;
    }

    if (ts.isFunctionDeclaration(node) && node.type) {
      const functionName = node.name?.getText(sourceFile) || "anonymous";
      const returnType = node.type.getText(sourceFile);
      functions[functionName] = returnType;
    }

    if (ts.isInterfaceDeclaration(node)) {
      interfaces.push(node.name.getText(sourceFile));
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);

  return { variables, functions, interfaces };
}

const code = ` 
  let myVar: number;
  function myFunc(): string { return ''; }
  interface MyInterface {
    hello: string;
    test: number;
  }
;`;

const astResult = parseAST(code);
console.log(astResult);
