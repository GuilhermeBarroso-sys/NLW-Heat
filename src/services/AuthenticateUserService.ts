/**
 * 1 Get Code (string)
 * 2 Recovery Authenticate token from github
 * 3 Recovery User info github
 * 4 Check if User Exists
 * 4 Yes => generate token
 * 4 No => Create user in DB and generate token
 * Return token with user info
 */
import axios from "axios"
import prismaClient from '../prisma';
import { sign } from 'jsonwebtoken'
interface IAccessTokenResponse {
  access_token: string
}
interface IUserResponse {
  avatar_url: string,
  login: string,
  id: number,
  name: string;
}
class AuthenticateUserService {
  async execute(code: string) {
    const url = "http://github.com/login/oauth/access_token";
    const { data: accessTokenResponse } = await axios.post<IAccessTokenResponse>(url, null, {
      params: {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code
      },
      headers: {
        "Accept": "application/json"
      }
    })
    
    const response = await axios.get<IUserResponse>("https://api.github.com/user", {
      headers: {
        authorization: `bearer ${accessTokenResponse.access_token}`
      }
    });
    const {login,id,avatar_url,name} = response.data
    let user = await prismaClient.user.findFirst({
      where: {
        github_id: id
      }
    })
    if(!user) {
      user = await prismaClient.user.create({
        data: {
          github_id: id,
          login,
          avatar_url,
          name
        }
      })
    }
    const token = sign( // 1:11:36
    {
      user: { // first parameter is All info where Client get access
        name: user.name,
        avatar_url: user.avatar_url,
        id: user.id
      },
    }, 
    process.env.JWT_SECRET, // 2 parameter is secret word used to validate
    {
      subject: user.id,
      expiresIn: "1d"
    }
    )
    return { token, user };
  }
}

export { AuthenticateUserService }