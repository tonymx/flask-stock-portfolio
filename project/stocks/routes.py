from . import stocks_blueprint
from flask import current_app, render_template, request, session, flash, redirect, url_for
from pydantic import BaseModel, validator, ValidationError
from project.models import Stock
from project import database
import click
from flask_login import login_required, current_user
from datetime import datetime


# -----------------
# Request Callbacks
# -----------------

@stocks_blueprint.before_request
def stocks_before_request():
    current_app.logger.info('Calling before_request() for the stocks blueprint...')


@stocks_blueprint.after_request
def stocks_after_request(response):
    current_app.logger.info('Calling after_request() for the stocks blueprint...')
    #print(response.header)
    return response


@stocks_blueprint.teardown_request
def stocks_teardown_request(error=None):
    current_app.logger.info('Calling teardown_request() for the stocks blueprint...')

# ------------
# CLI Commands
# ------------

@stocks_blueprint.cli.command('create_default_set')
def create_default_set():
    """Create three new stocks and add them to the database"""
    stock1 = Stock('HD', '25', '247.29')
    stock2 = Stock('TWTR', '230', '31.89')
    stock3 = Stock('DIS', '65', '118.77')
    database.session.add(stock1)
    database.session.add(stock2)
    database.session.add(stock3)
    database.session.commit()

@stocks_blueprint.cli.command('create')
@click.argument('symbol')
@click.argument('number_of_shares')
@click.argument('purchase_price')
def create(symbol, number_of_shares, purchase_price):
    """Create a new stock and add it to the database"""
    stock = Stock(symbol, number_of_shares, purchase_price)
    database.session.add(stock)
    database.session.commit()
    
# --------------
# Helper Classes
# --------------
class StockModel(BaseModel):
    """Class for parsing new stock data from a form."""
    stock_symbol: str
    number_of_shares: int
    purchase_price: float

    @validator('stock_symbol')
    def stock_symbol_check(cls, value):
        if not value.isalpha() or len(value) > 5:
            raise ValueError('Stock symbol must be 1-5 characters')
        return value.upper()
# ------
# Routes
# ------
@stocks_blueprint.route('/')
def index():
    current_app.logger.info('Calling the index() function.')
    return render_template('stocks/index.html')

@stocks_blueprint.route('/add_stock', methods=['GET', 'POST'])
@login_required  # NEW!
def add_stock():
    if request.method == 'POST':
        try:
            stock_data = StockModel(
                stock_symbol=request.form['stock_symbol'],
                number_of_shares=request.form['number_of_shares'],
                purchase_price=request.form['purchase_price']
            )
            print(stock_data)

            # Save the form data to the session object
            # session['stock_symbol'] = stock_data.stock_symbol
            # session['number_of_shares'] = stock_data.number_of_shares
            # session['purchase_price'] = stock_data.purchase_price

             # Save the form data to the database
            new_stock = Stock(stock_data.stock_symbol,
                              stock_data.number_of_shares,
                              stock_data.purchase_price,
                              current_user.id,    # NEW!
                              datetime.fromisoformat(request.form['purchase_date']))  # NEW!
            database.session.add(new_stock)
            database.session.commit()

            flash(f"Added new stock ({stock_data.stock_symbol})!", 'success')
            current_app.logger.info(f"Added new stock ({request.form['stock_symbol']})!")

            return redirect(url_for('stocks.list_stocks'))  # PREVIOUS: url_for('list_stocks')
        except ValidationError as e:
            print(e)

    return render_template('stocks/add_stock.html')  # PREVIOUS: return render_template('add_stock.html')

@stocks_blueprint.route('/stocks')
@login_required  # NEW!
def list_stocks():
    query = database.select(Stock).where(Stock.user_id == current_user.id).order_by(Stock.id)
    stocks = database.session.execute(query).scalars().all()

    current_account_value = 0.0
    for stock in stocks:
        stock.get_stock_data()
        database.session.add(stock)
        current_account_value += stock.get_stock_position_value()

    database.session.commit()
    return render_template('stocks/stocks.html', stocks=stocks, value=round(current_account_value, 2))


