G_SERVER_DEBUG = False
G_CLIENT_DEBUG = False  # Currently not used
G_DEBUG_PACKET_READ_FULLY = False


def trace(*args, g_debug=False):
    if (g_debug):
        print(*args)
