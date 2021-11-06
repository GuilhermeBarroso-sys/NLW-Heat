import {Request, Response, NextFunction} from 'express'
import { verify } from 'jsonwebtoken';
interface IPayload {
  sub: string
}
export function ensureAuthenticated(request : Request, response : Response, next : NextFunction) {
  const authToken = request.headers.authorization;

  if(!authToken) {
    return response.status(401).json({
      errorCode: "token.invalid"
    });
  }
  // Token Example: Bearer 8941294821948219fdfg
  // [0] First position of splited const: Bearer
  // [1] Second position of splited const: 8941294821948219fdfg
  const [, token] = authToken.split(" ");
  try{
    const { sub  } = verify(token, process.env.JWT_SECRET) as IPayload // sub is Id of user
    request.user_id = sub;
    return next();
  } catch(err) {
    return response.status(401).json({
      errorCode: "token.expired",
      exceptionError: err.message
    })
  }
}