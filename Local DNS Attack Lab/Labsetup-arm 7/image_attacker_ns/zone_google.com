$TTL 3D
@       IN      SOA   ns.google.com. admin.google.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.attacker32.com.

@       IN      A     10.9.0.14
www     IN      A     10.9.0.15
ns      IN      A     10.9.0.153
*       IN      A     10.9.0.16
