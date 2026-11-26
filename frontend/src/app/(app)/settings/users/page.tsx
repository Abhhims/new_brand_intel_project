"use client"

import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useForm, Controller } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { KeyRound, Loader2, Lock, Plus, Users } from "lucide-react"
import { PageHeader } from "@/components/app-shell"
import { EmptyState, SimpleSelect } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Role, type User } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { fmtDate } from "@/lib/format"
import { keys } from "@/lib/queries"

const ROLE_OPTIONS = [
  { value: "analyst", label: "Analyst" },
  { value: "admin", label: "Admin" },
]

const password = z.string().min(10, "Use at least 10 characters")

const createSchema = z.object({
  name: z.string().trim().min(1, "Enter a name").max(200),
  email: z.string().trim().regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Enter a valid email address"),
  password,
  role: z.enum(["analyst", "admin"]),
})
type CreateValues = z.infer<typeof createSchema>

function CreateUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const {
    register,
    control,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateValues>({ resolver: zodResolver(createSchema), defaultValues: { name: "", email: "", password: "", role: "analyst" } })
  const create = useMutation({
    mutationFn: api.createUser,
    onSuccess: (u) => {
      qc.invalidateQueries({ queryKey: keys.users })
      toast.success(`Created ${u.email}`)
      reset()
      onOpenChange(false)
    },
  })
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add a user</DialogTitle>
          <DialogDescription>Share the password with them securely. They can sign in straight away.</DialogDescription>
        </DialogHeader>
        <form className="space-y-3" noValidate onSubmit={handleSubmit((v) => create.mutateAsync(v).catch(() => {}))}>
          <div className="space-y-1.5">
            <Label htmlFor="u-name">Name</Label>
            <Input id="u-name" aria-invalid={!!errors.name} {...register("name")} />
            {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="u-email">Email</Label>
            <Input id="u-email" type="email" autoComplete="off" aria-invalid={!!errors.email} {...register("email")} />
            {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="u-password">Password</Label>
            <Input id="u-password" type="password" autoComplete="new-password" aria-invalid={!!errors.password} {...register("password")} />
            {errors.password ? (
              <p className="text-xs text-destructive">{errors.password.message}</p>
            ) : (
              <p className="text-xs text-muted-foreground">At least 10 characters</p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label>Role</Label>
            <Controller
              control={control}
              name="role"
              render={({ field }) => (
                <SimpleSelect ariaLabel="Role" value={field.value} onChange={field.onChange} options={ROLE_OPTIONS} className="w-full" />
              )}
            />
            <p className="text-xs text-muted-foreground">Admins can also manage brands, assets, allowlists and users.</p>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting && <Loader2 className="animate-spin" />}
              Add user
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ResetPasswordDialog({ user, onClose }: { user: User | null; onClose: () => void }) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<{ password: string }>({ resolver: zodResolver(z.object({ password })), defaultValues: { password: "" } })
  const update = useMutation({
    mutationFn: (p: string) => api.updateUser(user!.id, { password: p }),
    onSuccess: () => {
      toast.success(`Password reset for ${user?.email}`)
      reset()
      onClose()
    },
  })
  return (
    <Dialog open={!!user} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Reset password</DialogTitle>
          <DialogDescription>Set a new password for {user?.name}.</DialogDescription>
        </DialogHeader>
        <form className="space-y-3" noValidate onSubmit={handleSubmit((v) => update.mutateAsync(v.password).catch(() => {}))}>
          <div className="space-y-1.5">
            <Label htmlFor="new-password">New password</Label>
            <Input id="new-password" type="password" autoComplete="new-password" aria-invalid={!!errors.password} {...register("password")} />
            {errors.password ? (
              <p className="text-xs text-destructive">{errors.password.message}</p>
            ) : (
              <p className="text-xs text-muted-foreground">At least 10 characters</p>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting && <Loader2 className="animate-spin" />}
              Reset password
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default function UsersPage() {
  const { user: me, isAdmin } = useAuth()
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [resetting, setResetting] = useState<User | null>(null)
  const users = useQuery({ queryKey: keys.users, queryFn: api.users, enabled: isAdmin })
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof api.updateUser>[1] }) => api.updateUser(id, body),
    onSuccess: (u) => {
      qc.setQueryData<User[]>(keys.users, (prev) => prev?.map((x) => (x.id === u.id ? u : x)))
      toast.success(`Updated ${u.email}`)
    },
  })

  if (!isAdmin) {
    return (
      <EmptyState icon={Lock} title="Admins only">
        User management is limited to admins. Ask an admin if you need an account changed.
      </EmptyState>
    )
  }

  return (
    <>
      <PageHeader
        title="Users"
        description="Analysts review and triage alerts. Admins also manage brands and users."
        actions={
          <Button onClick={() => setCreating(true)}>
            <Plus />
            Add user
          </Button>
        }
      />
      <div className="overflow-hidden rounded-lg border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs text-muted-foreground">User</TableHead>
              <TableHead className="text-xs text-muted-foreground">Role</TableHead>
              <TableHead className="text-xs text-muted-foreground">Active</TableHead>
              <TableHead className="hidden text-xs text-muted-foreground md:table-cell">Added</TableHead>
              <TableHead className="text-right text-xs text-muted-foreground">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.isLoading &&
              Array.from({ length: 3 }).map((_, i) => (
                <TableRow key={i}>
                  <TableCell colSpan={5}>
                    <Skeleton className="h-6 w-full" />
                  </TableCell>
                </TableRow>
              ))}
            {users.data?.map((u) => {
              const self = u.id === me?.id
              return (
                <TableRow key={u.id} className={u.is_active ? undefined : "text-muted-foreground"}>
                  <TableCell>
                    <div className="font-medium">
                      {u.name}
                      {self && <span className="ml-1.5 text-xs font-normal text-muted-foreground">(you)</span>}
                    </div>
                    <div className="text-xs text-muted-foreground">{u.email}</div>
                  </TableCell>
                  <TableCell>
                    <SimpleSelect
                      ariaLabel={`Role for ${u.email}`}
                      size="sm"
                      value={u.role}
                      disabled={self || update.isPending}
                      onChange={(v) => v !== u.role && update.mutate({ id: u.id, body: { role: v as Role } })}
                      options={ROLE_OPTIONS}
                      className="w-28"
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={u.is_active}
                        disabled={self || update.isPending}
                        aria-label={u.is_active ? `Deactivate ${u.email}` : `Activate ${u.email}`}
                        onCheckedChange={(c) => update.mutate({ id: u.id, body: { is_active: c } })}
                      />
                      <span className="hidden text-xs sm:inline">{u.is_active ? "Active" : "Deactivated"}</span>
                    </div>
                  </TableCell>
                  <TableCell className="hidden text-sm md:table-cell">{fmtDate(u.created_at)}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => setResetting(u)}>
                      <KeyRound />
                      <span className="hidden sm:inline">Reset password</span>
                    </Button>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
        {users.data?.length === 0 && <EmptyState icon={Users} title="No users" />}
      </div>
      <CreateUserDialog open={creating} onOpenChange={setCreating} />
      <ResetPasswordDialog user={resetting} onClose={() => setResetting(null)} />
    </>
  )
}
