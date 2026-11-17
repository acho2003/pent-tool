import { Body, Controller, Get, Param, Post, Query, Res, UseGuards } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { AuthGuard } from '@nestjs/passport';
import { execSync } from 'child_process';
import { basename, join } from 'path';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly httpService: HttpService, private readonly usersService: UsersService) {}

  @Get()
  // ruleid: nestjs-route-without-guard
  findAll() {
    return this.usersService.findByName('x');
  }

  @UseGuards(AuthGuard('jwt'))
  @Get(':id')
  // ok: nestjs-route-without-guard
  findOne(@Param('id') id: string) {
    return this.usersService.findByName(id);
  }

  @Get('proxy')
  // ruleid: nestjs-route-without-guard
  async proxy(@Query('url') url: string) {
    // ruleid: nestjs-request-to-ssrf
    return this.httpService.get(url);
  }

  @Get('go')
  // ruleid: nestjs-route-without-guard
  go(@Query('next') next: string, @Res() res: any) {
    // ruleid: nestjs-request-to-redirect
    return res.redirect(next);
  }

  @Get('file')
  // ruleid: nestjs-route-without-guard
  file(@Query('name') name: string, @Res() res: any) {
    // ruleid: nestjs-request-to-file-path
    return res.sendFile(join('/srv/files', name));
  }

  @Get('safe-file')
  // ruleid: nestjs-route-without-guard
  safeFile(@Query('name') name: string, @Res() res: any) {
    // ok: nestjs-request-to-file-path
    return res.sendFile(join('/srv/files', basename(name)));
  }

  @Post('ping')
  // ruleid: nestjs-route-without-guard
  ping(@Body() body: any) {
    // ruleid: nestjs-request-to-command
    return execSync('ping -c 1 ' + body.host);
  }

  @Get('safe-go')
  // ruleid: nestjs-route-without-guard
  safeGo(@Res() res: any) {
    // ok: nestjs-request-to-redirect
    return res.redirect('/home');
  }
}
