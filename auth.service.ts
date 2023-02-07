import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { UsersService } from 'src/users/users.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
// import { ConfigService } from '@nestjs/config';
import { AuthDto, ChangePasswordDto, ConfirmOtpDto } from './dto/auth.dto';
import { PrismaService } from 'src/prisma.service';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    // private configService: ConfigService,
    private prisma: PrismaService,
    private mailerService: MailerService,
  ) {}
  async signUp(createUserDto: CreateUserDto): Promise<any> {
    // Check if user exists
    const userExists = await this.prisma.user.findUnique({
      where: { email: createUserDto.email },
    });
    if (userExists) {
      throw new BadRequestException('User already exists');
    }

    // Hash password
    const hash = await this.hashData(createUserDto.password);
    const newUser = await this.usersService.create({
      ...createUserDto,
      password: hash,
    });
    // const tokens = await this.getTokens(newUser.id, newUser.email);
    // await this.updateRefreshToken(newUser.id, tokens.refreshToken);
    // return tokens;
    return true;
  }

  async signIn(data: AuthDto) {
    // Check if user exists
    const user = await this.usersService.findByEmail(data.email);
    if (!user) throw new BadRequestException('User does not exist');
    const passwordMatches = await argon2.verify(user.password, data.password);
    if (!passwordMatches)
      throw new BadRequestException('Password is incorrect');
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    delete user.password;
    delete user.refreshToken;
    const mailSender = await this.sentOtp(data.email);
    return mailSender;
    // return { ...user, ...tokens };
  }

  async logout(userId: number) {
    const logout = await this.usersService.update(userId, {
      refreshToken: null,
    });
    if (logout) {
      return {
        status: true,
        message: `logout successfully`,
      };
    } else {
      return {
        status: false,
        message: `something went wrong`,
      };
    }
  }

  hashData(data: string) {
    return argon2.hash(data);
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    const hashedRefreshToken = await this.hashData(refreshToken);
    await this.usersService.update(userId, {
      refreshToken: hashedRefreshToken,
    });
  }

  async getTokens(userId: number, email: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: process.env.JWT_ACCESS_SECRET,
          expiresIn: '15m',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: '7d',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshTokens(userId: number, refreshToken: string) {
    const user = await this.usersService.findById(userId);
    if (!user || !user.refreshToken)
      throw new ForbiddenException('Access Denied');
    const refreshTokenMatches = await argon2.verify(
      user.refreshToken,
      refreshToken,
    );
    if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');
    const tokens = await this.getTokens(user.id, user.username);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    return tokens;
  }

  async sentOtp(email: string) {
    const otp = Math.floor(1000 + Math.random() * 9000);
    const response = await this.mailerService.sendMail({
      to: email,
      from: process.env.ADMIN_EMAIL,
      subject: `Validate your accout`,
      text: `Your OTP is ${otp}`,
    });
    if (response) {
      await this.prisma.user.update({
        where: { email: email },
        data: { otp: otp },
      });
      return {
        status: true,
        message: `OTP sent successfully to your email ${email}`,
        data: [],
      };
    } else {
      return {
        status: false,
        message: `Mail sending failed`,
        data: [],
      };
    }
  }

  async confirmOtp(data: ConfirmOtpDto) {
    // Check if user exists
    const user = await this.usersService.findByEmail(data.email);
    if (user.otp !== data.otp) throw new BadRequestException('Invalid OTP');
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    delete user.password;
    delete user.refreshToken;
    // const mailSender = await this.sentOtp(data.email);
    // return mailSender;
    return { ...user, ...tokens };
  }

  async changePassword(email: string, data: ChangePasswordDto) {
    const user = await this.usersService.findByEmail(email);
    if (!user) throw new BadRequestException('User does not exist');
    const passwordMatches = await argon2.verify(user.password, data.password);
    if (!passwordMatches)
      throw new BadRequestException('Password is incorrect');
    const hash = await this.hashData(data.newPassword);
    const changePassword = await this.prisma.user.update({
      where: { email: email },
      data: { password: hash },
    });
    if (changePassword) {
      return {
        status: true,
        message: `Password changed successfully`,
      };
    } else {
      throw new BadRequestException('Something went wrong');
    }
  }
}
