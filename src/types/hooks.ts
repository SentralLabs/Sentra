import type { User } from "./adapter.js";

type Hook<T> = (data: T) => void | Promise<void>;

export interface AuthHooks {
    beforeLogin?: Hook<User>;

    afterLogin?: Hook<User>;

    beforeSignUp?: Hook<SignUpHookData>;

    afterSignUp?: Hook<User>;

}

export interface SignUpHookData {
    email: string;
}
