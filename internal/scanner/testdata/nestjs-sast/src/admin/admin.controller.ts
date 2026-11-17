import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { RolesGuard } from '../auth/roles.guard';
import { Public } from '../auth/public.decorator';

@UseGuards(RolesGuard)
@Controller('admin')
export class AdminController {
  @Get()
  // ok: nestjs-route-without-guard
  list() {
    return [];
  }
}

@Controller('auth')
export class AuthController {
  @Public()
  @Post('login')
  // ok: nestjs-route-without-guard
  login(@Body() dto: any) {
    return dto;
  }
}
