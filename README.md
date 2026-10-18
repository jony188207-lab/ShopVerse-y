# ShopVerse Admin Panel
A separate Next.js 14 + TypeScript + Tailwind app for staff. It uses the **same Firebase project as the customer app: `shopverse21-831fc`**. Do not add it to the customer app.

This project holds **no Firebase rules, indexes or Cloud Functions**. Those live in the customer-app repository and are what actually protect your data. Menus and page guards here are only cosmetic.

## Honest status (read first)
| | |
|---|---|
| Written and reviewed | 14 screens, login, role gate, audit log writes. |
| **Not run** | `npm install`, `npm run build`, `typecheck`, `lint`, real vitest, and any test against your live Firebase. The authoring environment had no npm registry. Nothing was deployed. |
| Offline checks that did run | Import/export scan (47 files, 0 problems); every list query checked against the customer app's `firestore.indexes.json` (all covered); secrets scan (clean); 14 pure-logic tests (`lib/*.test.ts`) run with a small stand-in runner, **not real vitest**. |

## Pages and what each one needs
| Page | Min. role | Works on free Spark? |
|---|---|---|
| Dashboard (counts) | moderator | Yes |
| Products, Reviews, Videos, Reports (moderation) | moderator | Yes (direct Firestore writes + audit log) |
| Categories, Home banners | admin | Yes (images are https links; no Storage) |
| Stores (commission) | admin | Yes |
| Orders (read-only) | admin | Viewing yes. "Confirm COD remittance" needs Functions |
| Sellers (approve/reject/suspend) | admin | **No, needs Cloud Functions (Blaze)** |
| Users (suspend, roles) | admin / super_admin for roles | Search yes. Suspend and role change **need Functions** |
| Withdrawals | admin | **Needs Functions** |
| Announcements | admin | **Needs Functions** |
| Settings | super_admin | Yes |
| Audit log | admin | Yes |

Pages that need Functions show a notice and fail with a clear message ("probably not deployed") when the functions are absent. Nothing is faked. Cloud Functions require the paid Blaze plan; this project never enables it.

Admin cannot edit order status directly on purpose: stock, earnings and notifications are maintained by server triggers.

## Environment variables
Copy `.env.example` to `.env.local` (local) and set the same names in Vercel.
| Variable | Required | Value |
|---|---|---|
| `NEXT_PUBLIC_FIREBASE_API_KEY` | Yes | Console → Project settings → Your apps → Web app |
| `NEXT_PUBLIC_FIREBASE_APP_ID` | Yes | same place |
| `NEXT_PUBLIC_FIREBASE_PROJECT_ID` | Yes | `shopverse21-831fc` |
| `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN` | Yes | `shopverse21-831fc.firebaseapp.com` |
| `NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET` | No | `shopverse21-831fc.firebasestorage.app` |
| `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID` | No | `413026494596` |
| `NEXT_PUBLIC_FIREBASE_FUNCTIONS_REGION` | No | `us-central1` |
| `NEXT_PUBLIC_STOREFRONT_URL` | No | Customer app URL, no trailing slash. Adds "view in store" links. |

Never put a service-account key in any variable or in git. None is needed. `npm run check:env` lists missing variables without printing values. After changing variables in Vercel you must **redeploy**.

## Deploy on Vercel (from an Android phone)
Use Chrome with **Desktop site** on.
1. Put this project (with `package.json` at the repository root) in a **private** GitHub repository.
2. vercel.com → Add New → Project → import it. Framework: Next.js. Defaults for build.
3. Add the required variables for Production, then Deploy.
4. Firebase Console → Authentication → Settings → **Authorized domains** → add the admin panel's domain (without `https://`). Without this, login fails.
5. Keep the admin URL private. Pages send `noindex`, but that is not access control.

## Create the first super admin (Console only, no code)
1. Sign up in the customer app and verify the email (or add the user in Console → Authentication).
2. Copy the **User UID** from Authentication → Users.
3. Firestore Database → Start collection `roles` → Document ID = the UID → field `role` (string) = `super_admin`.
4. Sign in to the admin panel. Other staff roles are then set from the Users page (needs Functions) or the same way in the Console.

## Security model
* Roles come from `roles/{uid}`, which no client can write.
* Moderation writes carry an `adminLogs` entry in the same atomic batch; rules require `adminId` to be you.
* Rules grant admins broad write access on `orders`, `stores`, `products` and `videos`. This panel limits itself to safe fields, but the rules themselves are wider than the panel: keep admin accounts few and protected with strong passwords.

## Local commands (on a computer)
`npm install` · `npm run dev` · `npm run build` · `npm run typecheck` · `npm run lint` · `npm test` · `npm run check:env`

## Layout
`app/(panel)/` pages · `app/login/` · `components/` · `hooks/` · `lib/` (firebase init, callables, audit, formatting, errors, permissions + tests) · `config/` nav and default categories · `scripts/check-env.mjs`.
