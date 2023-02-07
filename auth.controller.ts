import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { AuthService } from './auth.service';
import { AuthDto, ChangePasswordDto, ConfirmOtpDto } from './dto/auth.dto';
import { AccessTokenGuard } from '../common/guards/accessToken.guard';
import { RefreshTokenGuard } from '../common/guards/refreshToken.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @HttpCode(201)
  async signup(@Body() createUserDto: CreateUserDto) {
    const created = await this.authService.signUp(createUserDto);
    if (created) {
      return {
        status: true,
        message: `User created Successfully`,
        data: [],
      };
    }
  }

  @Post('signin')
  signin(@Body() data: AuthDto) {
    return this.authService.signIn(data);
  }

  @UseGuards(AccessTokenGuard)
  @Get('logout')
  logout(@Req() req: Request) {
    const userId = req.user['sub'];
    return this.authService.logout(userId);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  refreshTokens(@Req() req: Request) {
    const userId = req.user['sub'];
    const refreshToken = req.user['refreshToken'];
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @Post('sendOtp')
  async sendEmail(@Body('email') email) {
    return await this.authService.sentOtp(email);
  }

  @Post('confirmOtp')
  confirmOtp(@Body() data: ConfirmOtpDto) {
    return this.authService.confirmOtp(data);
  }

  @UseGuards(AccessTokenGuard)
  @Post('changePassword')
  async changePassword(@Req() req, @Body() data: ChangePasswordDto) {
    const email = req.user['email'];
    return this.authService.changePassword(email, data);
  }

  @Post('forgetPassword')
  async forgetPassword(@Req() req) {}
}
