import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user)
        user.bid = basket.id // keep track of original basket
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  return (req: Request, res: Response, next: NextFunction) => {
    // Execute a parameterized SQL query to find a user with matching email and password
    models.sequelize.query(
      'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
      {
        replacements: {
          email: req.body.email || '', // Use the provided email or an empty string
          password: security.hash(req.body.password || '') // Hash the provided password or an empty string
        },
        model: models.User, // Use the User model for the query result
        plain: false // Return an array of results instead of a single object
      }
    ).then((authenticatedUser) => {
      // Convert the query result to JSON format
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          // User exists and has TOTP (Time-based One-Time Password) enabled
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data?.id) {
          // User exists and doesn't have TOTP enabled, proceed with login
          afterLogin(user, res, next)
        } else {
          // User not found or invalid credentials
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        // Pass any errors to the error handling middleware
        next(error)
      })
  }
