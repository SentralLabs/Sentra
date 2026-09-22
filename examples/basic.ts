import {createAuth} from "../src/index.js";
import { MemoryAdapter } from "../src/index.js";

const adapter = new MemoryAdapter();

const auth = createAuth({
    adapter,
    refreshTokenAdapter: adapter,
    secret: process.env.JWT_SECRET ?? "dev-only-secret-change-me-in-production!"
});
// signup
const res = await auth.signUp({
    email: "akash@gmail.com",
    password: "123"
});
// login
const { user, token } = await auth.login({
    email: "akash@gmail.com",
    password: "123"
});
// authentication
const authenticatedUser = await auth.authenticate(token);