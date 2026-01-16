from rest_framework.permissions import BasePermission

class IsAdminOrReadOnly(BasePermission):
    """
    Custom permission for public endpoints (Banner, Category, Event):
    - Anyone can read (GET) - no authentication required
    - Only admin can create/update/delete (POST/PUT/PATCH/DELETE)
    """
    def has_permission(self, request, view):
        if request.method in ['GET']: # Read-only methods for eveyone (even unauthenticated)
            return True        
        return request.user.is_authenticated and request.user.is_staff # only admin can perform write operations

class TicketPermission(BasePermission):
    """
    Custom permission for ticket operations:
    - Registered customers can create and view their own tickets (limited fields)
    - Only admin can update/delete and access all fields
    """
    
    def has_permission(self, request, view):
        """ Check if user has permission to access the endpoint """
        if not request.user.is_authenticated: # must be authenticated for any ticket operation
            return False
        if request.method in ['GET', 'POST']: # allow GET and POST for authenticated users
            return True
        if request.method in ['PUT', 'PATCH', 'DELETE']: # only admin can modify tickets UPDATE/DELETE
            return request.user.is_staff          
        return False
    
    def has_object_permission(self, request, view, obj):
        """ Check permissions for specific ticket object """
        if request.method == 'GET': # user can view their own tickets
            if obj.order and obj.order.customer == request.user:
                return True
            return request.user.is_staff # admin can view all tickets
        if request.method in ['PUT', 'PATCH', 'DELETE']: # only admin can modify tickets
            return request.user.is_staff             
        return False

class OrderPermission(BasePermission):
    """
    Custom permission for orders:
    - Authenticated users can create and view their own orders  
    - Only admin can update/delete orders
    """
    
    def has_permission(self, request, view):
        """ Check if user has permission to access orders """
        if not request.user.is_authenticated:
            return False        
        if request.method in ['GET', 'POST']:  # Allow authenticated users to GET and POST
            return True
        else:  # PUT, PATCH, DELETE - admin only
            return request.user.is_staff
    
    def has_object_permission(self, request, view, obj):
        """ Check permissions for specific order object """
        if request.method in ['GET', 'POST']:          
            return obj.customer == request.user or request.user.is_staff  # Users can view/create their own orders, admins can see all
        return request.user.is_staff  # Only admin can modify orders