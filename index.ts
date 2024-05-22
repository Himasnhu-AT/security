import {
  Node,
  isIdentifier,
  isPropertyAccessExpression,
  CallExpression,
  isCallExpression,
  MethodDeclaration,
  isMethodDeclaration,
  createSourceFile,
  ScriptTarget,
  forEachChild,
} from "typescript";

const sourceCode = `
import { ForbiddenException,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import SignUpDto from './dto/signup.dto';
import SignInDto from './dto/signin.dto';
import handleErrors from 'src/handlers/handleErrors.global';
import { JwtService } from '@nestjs/jwt';
import sendEmail from 'src/handlers/email.global';
import Redis from 'ioredis';
import { emit } from 'process';
import RetrieveInfoFromRequest from 'src/handlers/retriveInfoFromRequest.global';
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    @Inject('REDIS') private redisClient: Redis,
    private jwtService: JwtService,
  ) {}

  async sendVerificationCode(
    email: string,
    subject: string,
    text: string,
  ): Promise<boolean> {
    try {
      const res = await sendEmail(email, subject, text);
      return res;
    } catch (error) {
      return false;
    }
  }

  getHello(): string {
    return 'Hello from Auth Service!';
  }

  async signUp(body: SignUpDto) {
    const { name, email, password, userName } = body;

    if (!userName || !email || !password || !name) {
      throw new ForbiddenException('Missing required fields');
    }

    if (
      password.length < 8 ||
      !/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(
        password,
      )
    ) {
      throw new ForbiddenException(
        'Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character',
      );
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
      throw new ForbiddenException('Invalid email format');
    }

    //! @Himasnhu-AT Improve token generation logic
    const token = Math.random().toString(36).substring(2);
    let user = await this.prisma.user
      .create({
        data: {
          token,
          role: 'USER',
          name,
          email,
          password,
          userName,
        },
      })
      .catch((error) => {
        handleErrors(error);
      });

    //! @Himasnhu-AT Improve verification Code generation logic
    const verificationCode = Math.random().toString(36).substring(2);

    try {
      await this.redisClient.set(email, verificationCode);
    } catch (error) {
      return error;
    } finally {
      const subject = 'Email Verification';
      const text = \`Your verification code is \${verificationCode}\`;
      await this.sendVerificationCode(email, subject, text);
    }

    delete (user as { password: string }).password;
    return user;
  }

  async verifyEmail(body: { email: string; token: string }, response) {
    const verificationCode = await this.redisClient.get(body.email);

    if (verificationCode !== body.token) {
      throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
    }

    await this.redisClient.del(body.email);

    let user = await this.prisma.user.update({
      where: {
        email: body.email,
      },
      data: {
        isVerified: true,
      },
    });

    const payload = {
      sub: (user as { id: string }).id,
      email: (user as { email: string }).email,
      token: (user as { token: string }).token,
      userName: (user as { userName: string }).userName,
    };

    const access_token: string = this.jwtService.sign(payload) || '';

    // Set the access_token as a cookie
    response.cookie('access_token', access_token, { httpOnly: true });
    return { message: 'Email verified successfully' };
  }

  async forgotPassword(email: string) {
    await this.prisma.user
      .findUnique({
        where: {
          email: email,
        },
      })
      .catch((error) => {
        handleErrors(error);
      });

    //! @Himasnhu-AT Improve verification Code generation logic
    const verificationCode = Math.random().toString(36).substring(2);

    if (await this.redisClient.get(email)) {
      await this.redisClient.del(email);
    }

    try {
      await this.redisClient.set(email, verificationCode);
    } catch (error) {
      return error;
    } finally {
      const subject = 'Email Verification';
      const text = \`Your verification code is \${verificationCode}\`;
      await this.sendVerificationCode(email, subject, text);
    }
  }

  async forgotPasswordEmailVerify(body: {
    email: string;
    token: string;
    newPassword: string;
  }) {
    const verificationCode = await this.redisClient
      .get(body.email)
      .catch((error) => {
        throw new NotFoundException('Token not found for given Email');
      });

    if (body.token != verificationCode) {
      throw new ForbiddenException('Wrong verification Code.');
    }

    //! @Himasnhu-AT Hash this password
    await this.prisma.user.update({
      where: {
        email: body.email,
      },
      data: {
        password: body.newPassword,
      },
    });

    return \`Password changed successfully!\`;
  }

  async updatePassword(
    dto: { newPassword: string; oldPassword: string },
    request: any,
  ) {
    const { id, email } = RetrieveInfoFromRequest(request);

    const user = await this.prisma.user
      .findUnique({
        where: {
          id,
          email,
        },
      })
      .catch((error) => {
        handleErrors(error);
      });

    if (dto.oldPassword != (user as unknown as any).password) {
      await this.prisma.user
        .update({
          where: {
            id,
            email,
          },
          data: {
            password: dto.newPassword,
          },
        })
        .catch((error) => {
          handleErrors(error);
        });
    }

    return \`Password updated successfully!\`;
  }

  async signoutUser(id, email, response) {
    // const { id, email } = RetrieveInfoFromRequest(request);

    await this.prisma.user
      .update({
        where: {
          id,
          email,
        },
        data: {
          token: null,
        },
      })
      .catch((error) => {
        handleErrors(error);
      });

    response.cookie('access_token', '', { httpOnly: true });

    return \`SignOut Successful!\`;
  }

  async signIn(body: SignInDto, response) {
    console.log('body', body);
    const { email, password } = body;

    if (!email || !password) {
      throw new HttpException(
        'Missing required fields',
        HttpStatus.BAD_REQUEST,
      );
    }

    const token = Math.random().toString(36).substring(2);
    const user = await this.prisma.user
      .update({
        where: {
          email,
        },
        data: {
          token,
        },
      })
      .catch((error) => {
        handleErrors(error);
      });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    if (user.password !== password) {
      throw new HttpException('Invalid password', HttpStatus.UNAUTHORIZED);
    }

    const payload = {
      sub: (user as { id: string }).id,
      email: (user as { email: string }).email,
      token: (user as { token: string }).token,
      userName: (user as { userName: string }).userName,
    };

    const access_token: string = this.jwtService.sign(payload) || '';

    // Set the access_token as a cookie
    response.cookie('access_token', access_token, { httpOnly: true });

    delete (user as { password: string }).password;
    return user;
  }
}
`;

// Utility function to get the name of a node
const getNodeName = (node: Node): string => {
  if (isIdentifier(node)) {
    return node.getText();
  } else if (isPropertyAccessExpression(node)) {
    return node.name.getText();
  }
  return "";
};

// Utility function to find function calls by name
const findFunctionCallsByName = (
  node: Node,
  name: string,
  results: CallExpression[] = []
): CallExpression[] => {
  console.log(node);
  if (isCallExpression(node) && getNodeName(node.expression) === name) {
    results.push(node);
  }

  forEachChild(node, (child) => findFunctionCallsByName(child, name, results));
  console.log(results);
  return results;
};

// Utility function to find method declarations by name
const findMethodDeclarationsByName = (
  node: Node,
  name: string,
  results: MethodDeclaration[] = []
): MethodDeclaration[] => {
  if (isMethodDeclaration(node) && getNodeName(node.name) === name) {
    results.push(node);
  }

  forEachChild(node, (child) =>
    findMethodDeclarationsByName(child, name, results)
  );
  return results;
};

// Function to analyze the source code for security issues
const analyzeSourceCode = (sourceCode: string) => {
  const sourceFile = createSourceFile(
    "tempFile.ts",
    sourceCode,
    ScriptTarget.Latest,
    true
  );

  const securityIssues: string[] = [];

  // Check for insecure token generation
  const insecureTokenGenerationCalls = findFunctionCallsByName(
    sourceFile,
    "Math.random"
  );
  if (insecureTokenGenerationCalls.length > 0) {
    securityIssues.push("Insecure token generation found using Math.random.");
  }

  // Check for plain text password storage
  const signUpMethod = findMethodDeclarationsByName(sourceFile, "signUp")[0];
  if (signUpMethod && signUpMethod.body?.getText().includes("password")) {
    securityIssues.push(
      "Plain text password storage detected in signUp method."
    );
  }

  // Check for password hashing in forgotPasswordEmailVerify
  const forgotPasswordEmailVerifyMethod = findMethodDeclarationsByName(
    sourceFile,
    "forgotPasswordEmailVerify"
  )[0];
  if (
    forgotPasswordEmailVerifyMethod &&
    !forgotPasswordEmailVerifyMethod.body?.getText().includes("bcrypt")
  ) {
    securityIssues.push(
      "Password should be hashed in forgotPasswordEmailVerify method."
    );
  }

  // Check for missing validation
  const missingValidation = findMethodDeclarationsByName(
    sourceFile,
    "signUp"
  ).filter((method) => !method.parameters.some((param) => param.decorators));
  if (missingValidation.length > 0) {
    securityIssues.push("Missing validation in signUp method parameters.");
  }
  console.log(securityIssues);
  // Output the security issues found
  if (securityIssues.length > 0) {
    console.log("Security issues found:");
    securityIssues.forEach((issue) => console.log(`- ${issue}`));
  } else {
    console.log("No significant security issues found.");
  }
};

// Run the analysis on the provided source code
analyzeSourceCode(sourceCode);
